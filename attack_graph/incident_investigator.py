from __future__ import annotations

import argparse
import json
from pathlib import Path

import networkx as nx
import pandas as pd


REQUIRED_EVENT_COLUMNS = {
    "event_id",
    "start_time",
    "end_time",
    "src_ip",
    "dst_ip",
    "protocol",
    "attack_type",
    "flow_count",
    "mean_anomaly_score",
}

ATTACK_WEIGHTS = {
    "Heartbleed": 5.0,
    "Infiltration": 5.0,
    "DDoS": 4.0,
    "DoS Hulk": 4.0,
    "DoS GoldenEye": 4.0,
    "DoS Slowhttptest": 4.0,
    "DoS slowloris": 4.0,
    "PortScan": 3.0,
    "FTP-Patator": 3.0,
    "SSH-Patator": 3.0,
    "Bot": 3.0,
    "Web Attack - Brute Force": 3.0,
    "Web Attack - XSS": 3.0,
    "Web Attack - SQL Injection": 4.0,
}


def load_events(path: str) -> pd.DataFrame:
    events = pd.read_csv(path)

    missing = REQUIRED_EVENT_COLUMNS - set(events.columns)
    if missing:
        raise ValueError(
            f"attack_events.csv is missing required columns: {sorted(missing)}"
        )

    for column in ["start_time", "end_time"]:
        events[column] = pd.to_datetime(
            events[column],
            errors="coerce",
            utc=True,
            format="mixed",
        )

    if events[["start_time", "end_time"]].isna().any().any():
        raise ValueError("One or more event timestamps are invalid.")

    events["flow_count"] = pd.to_numeric(
        events["flow_count"], errors="coerce"
    ).fillna(0).astype(int)

    events["mean_anomaly_score"] = pd.to_numeric(
        events["mean_anomaly_score"], errors="coerce"
    )

    return events.sort_values("start_time").reset_index(drop=True)


def build_incident_evidence(
    events: pd.DataFrame,
    *,
    correlation_window_seconds: int = 300,
) -> pd.DataFrame:
    records: list[dict] = []

    for _, event in events.iterrows():
        same_source = events["src_ip"].eq(event["src_ip"])
        same_target = events["dst_ip"].eq(event["dst_ip"])

        time_gap = (
            events["start_time"] - event["end_time"]
        ).dt.total_seconds().abs()

        related_mask = (
            (events["event_id"] != event["event_id"])
            & (time_gap <= correlation_window_seconds)
            & (same_source | same_target)
        )

        related = events.loc[related_mask].copy()

        attack_type = str(event["attack_type"])
        anomaly = event["mean_anomaly_score"]

        # Lower Isolation Forest decision_function values are more anomalous.
        anomaly_component = 0.0
        if pd.notna(anomaly):
            anomaly_component = max(0.0, min(1.0, (0.05 - float(anomaly)) / 0.25))

        flow_component = min(1.0, float(event["flow_count"]) / 1000.0)
        attack_component = min(1.0, ATTACK_WEIGHTS.get(attack_type, 2.0) / 5.0)

        triage_score = (
            0.45 * anomaly_component
            + 0.20 * flow_component
            + 0.35 * attack_component
        )

        related_ids = related["event_id"].astype(str).tolist()
        related_types = sorted(related["attack_type"].astype(str).unique().tolist())

        records.append(
            {
                "event_id": event["event_id"],
                "incident_start": event["start_time"].isoformat(),
                "incident_end": event["end_time"].isoformat(),
                "src_ip": event["src_ip"],
                "dst_ip": event["dst_ip"],
                "protocol": event["protocol"],
                "attack_type": attack_type,
                "flow_count": int(event["flow_count"]),
                "mean_anomaly_score": (
                    None if pd.isna(anomaly) else float(anomaly)
                ),
                "related_event_count": int(len(related)),
                "related_event_ids": related_ids,
                "related_attack_types": related_types,
                "triage_score": round(float(triage_score), 6),
            }
        )

    return pd.DataFrame(records)


def build_graph_context(graph_path: str | None, events: pd.DataFrame) -> dict:
    if not graph_path:
        return {}

    path = Path(graph_path)
    if not path.exists():
        raise FileNotFoundError(f"Attack graph not found: {path}")

    graph = nx.read_gexf(path)

    context = {}
    for event_id in events["event_id"].astype(str):
        node = f"event:{event_id}"
        if node not in graph:
            continue

        predecessors = [
            str(node_id)
            for node_id, attrs in graph.pred[node].items()
            if attrs.get("relation") in {"precedes", "initiates", "contains"}
        ]
        successors = [
            str(node_id)
            for node_id, attrs in graph[node].items()
            if attrs.get("relation") in {"precedes", "classified_as", "targets"}
        ]

        context[event_id] = {
            "graph_predecessors": predecessors,
            "graph_successors": successors,
            "degree": int(graph.degree(node)),
        }

    return context


def write_report(
    evidence: pd.DataFrame,
    graph_context: dict,
    output_dir: Path,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    evidence_path = output_dir / "incident_investigation.csv"
    evidence.to_csv(evidence_path, index=False)

    payload = []
    for _, row in evidence.iterrows():
        item = row.to_dict()
        item["graph_context"] = graph_context.get(str(row["event_id"]), {})
        payload.append(item)

    (output_dir / "incident_investigation.json").write_text(
        json.dumps(payload, indent=2, default=str),
        encoding="utf-8",
    )

    lines = [
        "# CICIDS2017 Incident Investigation Report",
        "",
        f"- Events investigated: **{len(evidence):,}**",
        f"- Correlated events: **{int((evidence['related_event_count'] > 0).sum()):,}**",
        "",
        "## Event Findings",
        "",
        "| Event | Attack Type | Source | Target | Flows | Mean Anomaly | Related Events | Triage Score |",
        "|---|---|---|---|---:|---:|---:|---:|",
    ]

    ranked = evidence.sort_values(
        ["triage_score", "start_time"],
        ascending=[False, True],
    )

    for _, row in ranked.iterrows():
        lines.append(
            f"| {row['event_id']} | {row['attack_type']} | "
            f"{row['src_ip']} | {row['dst_ip']} | {int(row['flow_count'])} | "
            f"{row['mean_anomaly_score']:.6f} | {int(row['related_event_count'])} | "
            f"{row['triage_score']:.6f} |"
        )

    lines.extend(
        [
            "",
            "## Investigation Notes",
            "",
            "Each event is correlated with nearby events within the configured time window "
            "when they share a source or destination. The report preserves the raw event "
            "evidence and graph neighborhood instead of inventing missing network metadata.",
            "",
        ]
    )

    (output_dir / "incident_investigation_report.md").write_text(
        "\n".join(lines),
        encoding="utf-8",
    )


def run(
    events_path: str,
    output_dir: str,
    graph_path: str | None = None,
    correlation_window_seconds: int = 300,
) -> None:
    events = load_events(events_path)
    evidence = build_incident_evidence(
        events,
        correlation_window_seconds=correlation_window_seconds,
    )
    graph_context = build_graph_context(graph_path, events)
    write_report(evidence, graph_context, Path(output_dir))

    print("INCIDENT INVESTIGATION")
    print("=" * 60)
    print(f"Events investigated : {len(events):,}")
    print(
        "Events with nearby related evidence : "
        f"{int((evidence['related_event_count'] > 0).sum()):,}"
    )
    print(
        "Events with graph context            : "
        f"{len(graph_context):,}"
    )
    print(f"Output directory    : {output_dir}")
    print("Created:")
    print("  incident_investigation.csv")
    print("  incident_investigation.json")
    print("  incident_investigation_report.md")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate deterministic incident-investigation evidence from attack events and an attack graph."
    )
    parser.add_argument("events_path")
    parser.add_argument("--graph", default=None)
    parser.add_argument("--output-dir", default="incident_investigation_output")
    parser.add_argument("--window-seconds", type=int, default=300)
    args = parser.parse_args()

    run(
        args.events_path,
        args.output_dir,
        graph_path=args.graph,
        correlation_window_seconds=args.window_seconds,
    )
