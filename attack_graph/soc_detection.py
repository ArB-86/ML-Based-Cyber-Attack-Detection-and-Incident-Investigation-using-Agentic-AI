"""Explainable behavioural detections independent of CICIDS ground-truth labels."""
from __future__ import annotations

from dataclasses import dataclass
import pandas as pd

from .event_builder import normalize_columns


@dataclass(frozen=True)
class BehaviourThresholds:
    time_window_seconds: int = 300
    port_scan_unique_ports: int = 10
    horizontal_scan_unique_targets: int = 10
    source_fanout_unique_targets: int = 15
    ddos_unique_sources: int = 15
    ddos_min_flows: int = 40
    brute_force_min_flows: int = 12


AUTH_PORTS = {21, 22, 23, 25, 110, 143, 445, 3389, 5900}


def detect_behavioral_alerts(
    flows: pd.DataFrame,
    thresholds: BehaviourThresholds = BehaviourThresholds(),
) -> pd.DataFrame:
    """Return row-aligned rule flags/reasons; never read the Label column.

    Fixed time buckets make this batch detector reproducible, but activity that
    crosses a bucket boundary can be missed. Production streaming should use
    stateful rolling windows.
    """
    if flows.empty:
        return pd.DataFrame(
            {"rule_alert": False, "detection_reasons": "", "rule_count": 0},
            index=flows.index,
        )

    work = normalize_columns(flows).copy()
    work.columns = [str(c).strip().lower() for c in work.columns]
    required = {"timestamp", "src_ip", "dst_ip"}
    missing = required - set(work.columns)
    if missing:
        raise ValueError(f"Behavioural rules require columns: {sorted(missing)}")

    work["timestamp"] = pd.to_datetime(
        work["timestamp"], errors="coerce", utc=True, format="mixed"
    )
    if work["timestamp"].isna().any():
        raise ValueError("Behavioural rules received invalid or missing timestamps.")
    work["src_ip"] = work["src_ip"].astype(str).str.strip()
    work["dst_ip"] = work["dst_ip"].astype(str).str.strip()
    bucket = max(1, int(thresholds.time_window_seconds))
    work["_window"] = work["timestamp"].dt.floor(f"{bucket}s")
    work["_dst_port"] = (
        pd.to_numeric(work["dst_port"], errors="coerce")
        if "dst_port" in work.columns
        else pd.Series(pd.NA, index=work.index, dtype="Float64")
    )

    masks: dict[str, pd.Series] = {}
    false_mask = pd.Series(False, index=work.index)
    if work["_dst_port"].notna().any():
        pair_ports = work.groupby(
            ["_window", "src_ip", "dst_ip"], dropna=False
        )["_dst_port"].transform("nunique")
        masks["PORT_SCAN"] = pair_ports >= thresholds.port_scan_unique_ports

        service_targets = work.groupby(
            ["_window", "src_ip", "_dst_port"], dropna=False
        )["dst_ip"].transform("nunique")
        masks["HORIZONTAL_SCAN"] = (
            service_targets >= thresholds.horizontal_scan_unique_targets
        )

        auth = work["_dst_port"].isin(AUTH_PORTS)
        auth_attempts = work.groupby(
            ["_window", "src_ip", "dst_ip", "_dst_port"], dropna=False
        )["timestamp"].transform("size")
        masks["BRUTE_FORCE_PATTERN"] = (
            auth & (auth_attempts >= thresholds.brute_force_min_flows)
        )
    else:
        masks["PORT_SCAN"] = false_mask.copy()
        masks["HORIZONTAL_SCAN"] = false_mask.copy()
        masks["BRUTE_FORCE_PATTERN"] = false_mask.copy()

    source_fanout = work.groupby(
        ["_window", "src_ip"], dropna=False
    )["dst_ip"].transform("nunique")
    masks["HIGH_SOURCE_FANOUT"] = (
        source_fanout >= thresholds.source_fanout_unique_targets
    )

    target_sources = work.groupby(
        ["_window", "dst_ip"], dropna=False
    )["src_ip"].transform("nunique")
    target_flows = work.groupby(
        ["_window", "dst_ip"], dropna=False
    )["timestamp"].transform("size")
    masks["DISTRIBUTED_DOS_PATTERN"] = (
        (target_sources >= thresholds.ddos_unique_sources)
        & (target_flows >= thresholds.ddos_min_flows)
    )

    reasons_by_position: list[list[str]] = [[] for _ in range(len(work))]
    for reason, mask in masks.items():
        active_positions = mask.fillna(False).to_numpy(dtype=bool).nonzero()[0]
        for position in active_positions:
            reasons_by_position[position].append(reason)

    result = pd.DataFrame(index=work.index)
    result["rule_alert"] = [bool(items) for items in reasons_by_position]
    result["detection_reasons"] = [
        ";".join(sorted(set(items))) for items in reasons_by_position
    ]
    result["rule_count"] = [len(set(items)) for items in reasons_by_position]
    return result.reindex(flows.index)


def merge_detector_outputs(
    flows: pd.DataFrame,
    *,
    anomaly_threshold: float | None = None,
) -> pd.DataFrame:
    """OR together behavioural and Isolation Forest alerts without using labels."""
    out = flows.copy()
    rules = detect_behavioral_alerts(out)
    out["rule_alert"] = rules["rule_alert"].astype(bool)
    reasons = rules["detection_reasons"].fillna("").astype(str)

    if "anomaly_score" in out.columns and anomaly_threshold is not None:
        scores = pd.to_numeric(out["anomaly_score"], errors="coerce")
        out["model_alert"] = scores < float(anomaly_threshold)
    elif "predicted_anomaly" in out.columns:
        flags = out["predicted_anomaly"]
        if flags.dtype == object:
            out["model_alert"] = flags.astype(str).str.strip().str.lower().isin(
                {"true", "1", "yes", "y"}
            )
        else:
            out["model_alert"] = flags.fillna(False).astype(bool)
    else:
        out["model_alert"] = False

    model_flags = out["model_alert"].fillna(False).astype(bool)
    out["alert"] = out["rule_alert"] | model_flags
    reasons.loc[model_flags & reasons.eq("")] = "ISOLATION_FOREST_ANOMALY"
    both = model_flags & reasons.ne("")
    reasons.loc[both] = reasons.loc[both] + ";ISOLATION_FOREST_ANOMALY"
    out["detection_reasons"] = reasons
    out["alert_sources"] = [
        ";".join(name for name, active in (
            ("BEHAVIOURAL_RULE", bool(rule)),
            ("ISOLATION_FOREST", bool(model)),
        ) if active)
        for rule, model in zip(out["rule_alert"], out["model_alert"])
    ]
    return out
