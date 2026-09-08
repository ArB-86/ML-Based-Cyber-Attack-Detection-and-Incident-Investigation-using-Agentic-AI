from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

import pandas as pd


METADATA_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
]

BASE_COLUMNS = ["protocol", "label"]


@dataclass(frozen=True)
class EventConfig:
    """Rules for turning suspicious flows into attack events."""

    time_window_seconds: int = 60
    max_flows_per_event: int = 5000
    use_ports_in_key: bool = False


def _first_existing(columns: Iterable[str], aliases: Iterable[str]) -> Optional[str]:
    columns = set(columns)
    for alias in aliases:
        if alias in columns:
            return alias
    return None


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize common CICIDS column names to a canonical schema."""
    out = df.copy()
    out.columns = [str(c).strip() for c in out.columns]

    aliases = {
        "timestamp": ["timestamp", "Timestamp", "Flow Start", "Date time"],
        "src_ip": ["src_ip", "Source IP", "SourceIP", "Src IP"],
        "dst_ip": ["dst_ip", "Destination IP", "DestinationIP", "Dst IP"],
        "src_port": ["src_port", "Source Port", "SourcePort", "Src Port"],
        "dst_port": ["dst_port", "Destination Port", "DestinationPort", "Dst Port"],
        "protocol": ["protocol", "Protocol"],
        "label": ["label", "Label", "Attack", "Attack Type"],
        "anomaly_score": ["anomaly_score", "Anomaly Score"],
        "predicted_anomaly": ["predicted_anomaly", "Predicted Anomaly"],
    }

    rename = {}
    for canonical, names in aliases.items():
        actual = _first_existing(out.columns, names)
        if actual and actual != canonical:
            rename[actual] = canonical

    return out.rename(columns=rename)


def validate_event_input(df: pd.DataFrame, require_metadata: bool = True) -> dict:
    """Return a structured schema report; do not fabricate missing metadata."""
    normalized = normalize_columns(df)
    missing_base = [c for c in BASE_COLUMNS if c not in normalized.columns]
    missing_meta = [c for c in METADATA_COLUMNS if c not in normalized.columns]

    return {
        "valid_base": not missing_base,
        "valid_metadata": not missing_meta,
        "missing_base_columns": missing_base,
        "missing_metadata_columns": missing_meta,
        "metadata_available": not missing_meta,
        "usable_for_temporal_source_target_graph": (
            not missing_meta and not missing_base
        ),
        "require_metadata": require_metadata,
    }


def _build_key(row: pd.Series, use_ports: bool) -> tuple:
    key = (
        row["src_ip"],
        row["dst_ip"],
        str(row["protocol"]),
        str(row["label"]),
    )
    if use_ports:
        key += (row["src_port"], row["dst_port"])
    return key


def build_attack_events(
    df: pd.DataFrame,
    *,
    anomalous_only: bool = True,
    threshold: Optional[float] = None,
    config: EventConfig = EventConfig(),
) -> pd.DataFrame:
    """Group suspicious metadata-rich flows into attack events."""

    normalized = normalize_columns(df)
    report = validate_event_input(normalized)

    if not report["valid_base"]:
        raise ValueError(
            f"Missing required base columns: {report['missing_base_columns']}"
        )

    if not report["valid_metadata"]:
        raise ValueError(
            "Attack-event grouping for the temporal/source-target graph requires "
            f"these metadata columns: {report['missing_metadata_columns']}. "
            "The current CICIDS `no-metadata` files cannot support this operation."
        )

    work = normalized.copy()

    # CICIDS CSVs can contain multiple date representations across files.
    # format='mixed' avoids coercing valid timestamps simply because another
    # row uses a different representation.
    work["timestamp"] = pd.to_datetime(
        work["timestamp"],
        errors="coerce",
        utc=True,
        format="mixed",
    )

    if work["timestamp"].isna().any():
        bad_count = int(work["timestamp"].isna().sum())
        raise ValueError(
            f"One or more rows have an invalid/missing timestamp ({bad_count} rows)."
        )

    if anomalous_only:
        if "predicted_anomaly" in work.columns:
            work = work[work["predicted_anomaly"].astype(bool)].copy()
        elif threshold is not None and "anomaly_score" in work.columns:
            work = work[work["anomaly_score"] < threshold].copy()
        else:
            work = work[
                work["label"].astype(str).str.lower() != "benign"
            ].copy()

    work = work.sort_values("timestamp").copy()

    if work.empty:
        return pd.DataFrame(
            columns=[
                "event_id",
                "start_time",
                "end_time",
                "duration_seconds",
                "src_ip",
                "dst_ip",
                "protocol",
                "attack_type",
                "flow_count",
                "mean_anomaly_score",
                "ports_observed",
            ]
        )

    events = []
    current = None

    for _, row in work.iterrows():
        key = _build_key(row, config.use_ports_in_key)

        if current is None:
            current = {"key": key, "rows": [row]}
            continue

        last_row = current["rows"][-1]
        gap = (row["timestamp"] - last_row["timestamp"]).total_seconds()

        can_join = (
            key == current["key"]
            and gap <= config.time_window_seconds
            and len(current["rows"]) < config.max_flows_per_event
        )

        if can_join:
            current["rows"].append(row)
        else:
            events.append(current)
            current = {"key": key, "rows": [row]}

    events.append(current)

    output = []

    for idx, event in enumerate(events, start=1):
        rows = pd.DataFrame(event["rows"])
        scores = (
            pd.to_numeric(rows.get("anomaly_score"), errors="coerce")
            if "anomaly_score" in rows
            else None
        )

        output.append(
            {
                "event_id": f"EVT-{idx:05d}",
                "start_time": rows["timestamp"].min(),
                "end_time": rows["timestamp"].max(),
                "duration_seconds": (
                    rows["timestamp"].max() - rows["timestamp"].min()
                ).total_seconds(),
                "src_ip": rows["src_ip"].iloc[0],
                "dst_ip": rows["dst_ip"].iloc[0],
                "protocol": rows["protocol"].iloc[0],
                "attack_type": rows["label"].iloc[0],
                "flow_count": len(rows),
                "mean_anomaly_score": (
                    None if scores is None else scores.mean()
                ),
                "ports_observed": sorted(
                    set(
                        zip(
                            rows["src_port"].tolist(),
                            rows["dst_port"].tolist(),
                        )
                    )
                ),
            }
        )

    return pd.DataFrame(output)
