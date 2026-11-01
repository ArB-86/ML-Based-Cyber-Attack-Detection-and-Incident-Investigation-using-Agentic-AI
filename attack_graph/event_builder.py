"""Canonical flow schema and compatibility event-builder adapter.

Operational event formation is implemented in soc_investigation. This module
owns shared schema normalization and routes legacy event calls into the same
event contract. Ground-truth dataset labels are never used to select alerts.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

import pandas as pd


METADATA_COLUMNS = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port"]
BASE_COLUMNS = ["protocol"]


@dataclass(frozen=True)
class EventConfig:
    """Compatibility settings for callers of the historical event API."""

    time_window_seconds: int = 60
    max_flows_per_event: int = 5000
    use_ports_in_key: bool = False


def _first_existing(columns: Iterable[str], aliases: Iterable[str]) -> Optional[str]:
    available = {str(column).strip().lower(): column for column in columns}
    for alias in aliases:
        actual = available.get(str(alias).strip().lower())
        if actual is not None:
            return actual
    return None


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize CICIDS/flow field aliases without altering feature names."""
    out = df.copy()
    out.columns = [str(column).strip() for column in out.columns]
    aliases = {
        "timestamp": ["timestamp", "Flow Start", "Date time"],
        "src_ip": ["src_ip", "Source IP", "SourceIP", "Src IP"],
        "dst_ip": ["dst_ip", "Destination IP", "DestinationIP", "Dst IP"],
        "src_port": ["src_port", "Source Port", "SourcePort", "Src Port"],
        "dst_port": ["dst_port", "Destination Port", "DestinationPort", "Dst Port"],
        "protocol": ["protocol"],
        "label": ["label", "Attack", "Attack Type"],
        "anomaly_score": ["anomaly_score", "Anomaly Score"],
        "predicted_anomaly": ["predicted_anomaly", "Predicted Anomaly"],
        "model_alert": ["model_alert", "Model Alert"],
        "rule_alert": ["rule_alert", "Rule Alert"],
        "alert": ["alert", "Alert"],
        "alert_sources": ["alert_sources", "Alert Sources"],
        "detection_reasons": ["detection_reasons", "Detection Reasons"],
    }

    rename: dict[str, str] = {}
    lower_to_original = {str(column).strip().lower(): column for column in out.columns}
    for canonical, names in aliases.items():
        already_present = lower_to_original.get(canonical)
        if already_present is not None:
            if already_present != canonical:
                rename[already_present] = canonical
            continue
        actual = _first_existing(out.columns, names)
        if actual is not None and actual != canonical:
            rename[actual] = canonical
    return out.rename(columns=rename)


def validate_event_input(df: pd.DataFrame, require_metadata: bool = True) -> dict:
    """Return schema diagnostics; labels are optional and never required."""
    normalized = normalize_columns(df)
    missing_base = [column for column in BASE_COLUMNS if column not in normalized.columns]
    required_metadata = ["timestamp", "src_ip", "dst_ip"]
    if require_metadata:
        required_metadata.append("src_port")
        required_metadata.append("dst_port")
    missing_meta = [column for column in required_metadata if column not in normalized.columns]
    return {
        "valid_base": not missing_base,
        "valid_metadata": not missing_meta,
        "missing_base_columns": missing_base,
        "missing_metadata_columns": missing_meta,
        "metadata_available": not missing_meta,
        "usable_for_temporal_source_target_graph": not missing_base and not missing_meta,
        "require_metadata": require_metadata,
    }


def _as_bool(values: pd.Series) -> pd.Series:
    if pd.api.types.is_bool_dtype(values):
        return values.fillna(False)
    if pd.api.types.is_numeric_dtype(values):
        return pd.to_numeric(values, errors="coerce").fillna(0).ne(0)
    return values.astype(str).str.strip().str.lower().isin({"true", "1", "yes", "y"})


def build_attack_events(
    df: pd.DataFrame,
    *,
    anomalous_only: bool = True,
    threshold: float | None = None,
    config: EventConfig = EventConfig(),
) -> pd.DataFrame:
    """Compatibility adapter into the canonical SOC event builder.

    Alert selection uses an explicit alert/prediction/score only. It never
    falls back to CICIDS Label values because labels are evaluation ground
    truth, not operational detector output.
    """
    normalized = normalize_columns(df)
    required = {"timestamp", "src_ip", "dst_ip", "protocol"}
    missing = required - set(normalized.columns)
    if missing:
        raise ValueError(f"Missing required flow metadata columns: {sorted(missing)}")
    if config.time_window_seconds < 0 or config.max_flows_per_event < 1:
        raise ValueError("Event time window must be non-negative and max flows must be positive.")

    work = normalized.copy()
    work["timestamp"] = pd.to_datetime(
        work["timestamp"], errors="coerce", utc=True, format="mixed"
    )
    if work["timestamp"].isna().any():
        raise ValueError(
            f"Invalid/missing timestamps in {int(work['timestamp'].isna().sum())} flow rows."
        )

    if anomalous_only:
        if "alert" in work.columns:
            work["alert"] = _as_bool(work["alert"])
        elif "predicted_anomaly" in work.columns:
            work["alert"] = _as_bool(work["predicted_anomaly"])
        elif threshold is not None and "anomaly_score" in work.columns:
            scores = pd.to_numeric(work["anomaly_score"], errors="coerce")
            work["alert"] = scores < float(threshold)
        else:
            raise ValueError(
                "Cannot select suspicious flows without an explicit alert, "
                "predicted_anomaly or anomaly_score + threshold. Dataset Label "
                "is intentionally not used for operational alert selection."
            )
        work = work.loc[work["alert"]].copy()
    else:
        work["alert"] = True
        if "detection_reasons" not in work.columns:
            work["detection_reasons"] = "UNFILTERED_EVENT_IMPORT"
        if "alert_sources" not in work.columns:
            work["alert_sources"] = "LEGACY_EVENT_ADAPTER"

    if "detection_reasons" not in work.columns:
        source = "ISOLATION_FOREST_ANOMALY" if "predicted_anomaly" in work.columns or threshold is not None else "EXPLICIT_ALERT"
        work["detection_reasons"] = source
    if "alert_sources" not in work.columns:
        work["alert_sources"] = "LEGACY_EVENT_ADAPTER"

    from .soc_investigation import build_soc_events

    events = build_soc_events(
        work,
        event_gap_seconds=config.time_window_seconds,
        max_flows_per_event=config.max_flows_per_event,
        use_ports_in_key=config.use_ports_in_key,
    )
    if events.empty:
        events["ports_observed"] = pd.Series(dtype=object)
    else:
        events["ports_observed"] = events.apply(
            lambda row: sorted({
                (src_port, dst_port)
                for src_port in row["src_ports"]
                for dst_port in row["dst_ports"]
            }),
            axis=1,
        )
    return events
