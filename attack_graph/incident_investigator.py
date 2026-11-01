"""Backward-compatible CLI for the shared SOC investigation orchestrator.

This module no longer implements a second triage or reporting algorithm.
Legacy event CSVs are adapted to the canonical event contract and passed
through the same graph, incident, risk and evidence-tool stages used by the
end-to-end pipeline.
"""
from __future__ import annotations

import argparse
import ast
from pathlib import Path
import warnings

import pandas as pd

from .soc_investigation import run_soc_investigation_from_events


def load_events(path: str) -> pd.DataFrame:
    events = pd.read_csv(path)
    required = {
        "event_id", "start_time", "end_time", "src_ip", "dst_ip",
        "protocol", "flow_count",
    }
    missing = required - set(events.columns)
    if missing:
        raise ValueError(f"Event file is missing required columns: {sorted(missing)}")

    for column in ("start_time", "end_time"):
        events[column] = pd.to_datetime(events[column], errors="coerce", utc=True, format="mixed")
    if events[["start_time", "end_time"]].isna().any().any():
        raise ValueError("Event file contains invalid timestamps.")
    events["flow_count"] = pd.to_numeric(events["flow_count"], errors="coerce").fillna(0).astype(int)

    # Historical `attack_type` often came directly from CICIDS Label. Preserve
    # it for display only; it must not become an operational detection reason.
    events["detection_reasons"] = "LEGACY_EVENT_IMPORT"
    events["alert_sources"] = "LEGACY_EVENT_IMPORT"
    if "mean_anomaly_score" not in events.columns:
        events["mean_anomaly_score"] = pd.NA
    else:
        events["mean_anomaly_score"] = pd.to_numeric(events["mean_anomaly_score"], errors="coerce")

    if "dst_ports" not in events.columns:
        ports_column = events.get("ports_observed", pd.Series([None] * len(events)))
        parsed_ports = []
        for value in ports_column:
            ports = set()
            if isinstance(value, str) and value.strip():
                try:
                    pairs = ast.literal_eval(value)
                    for pair in pairs:
                        if isinstance(pair, (list, tuple)) and len(pair) == 2:
                            try:
                                ports.add(int(pair[1]))
                            except (TypeError, ValueError):
                                continue
                except (SyntaxError, ValueError):
                    pass
            parsed_ports.append(sorted(port for port in ports if 0 <= port <= 65535))
        events["dst_ports"] = parsed_ports
    return events


def run(
    events_path: str,
    output_dir: str,
    graph_path: str | None = None,
    correlation_window_seconds: int = 300,
) -> None:
    """Run the shared investigation stages on an existing event CSV.

    `graph_path` and `correlation_window_seconds` remain accepted for CLI
    compatibility. The canonical graph is rebuilt from the event contract
    using the same configured graph-correlation rules as the full pipeline.
    """
    if graph_path:
        warnings.warn(
            "A prebuilt graph is not loaded by the legacy adapter; the canonical graph is rebuilt from events.",
            DeprecationWarning,
            stacklevel=2,
        )
    events = load_events(events_path)
    _, graph, summary = run_soc_investigation_from_events(events, Path(output_dir))
    print("SOC INCIDENT INVESTIGATION")
    print("=" * 60)
    print(f"Events investigated : {summary['event_count']:,}")
    print(f"Candidate incidents : {summary['incident_count']:,}")
    print(f"Graph nodes / edges : {graph.number_of_nodes():,} / {graph.number_of_edges():,}")
    print(f"Agent tool calls    : {summary['agent_tool_calls']:,}")
    print(f"Output directory    : {output_dir}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Compatibility adapter to the shared SOC incident investigation workflow."
    )
    parser.add_argument("events_path")
    parser.add_argument("--graph", default=None)
    parser.add_argument("--output-dir", default="incident_investigation_output")
    parser.add_argument("--window-seconds", type=int, default=300)
    args = parser.parse_args()
    run(args.events_path, args.output_dir, args.graph, args.window_seconds)
