from __future__ import annotations

import networkx as nx
import pandas as pd


def _gexf_safe(value):
    """Convert pandas/numpy values to GEXF-compatible Python types."""
    if value is None:
        return None
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    if isinstance(value, (pd.Series, pd.DataFrame)):
        return str(value)
    if hasattr(value, "item"):
        try:
            value = value.item()
        except Exception:
            pass
    if isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _sanitize_graph_for_gexf(graph: nx.DiGraph) -> nx.DiGraph:
    """Return a copy whose node/edge attributes are GEXF-safe."""
    safe_graph = nx.DiGraph()
    safe_graph.graph.update(
        {k: _gexf_safe(v) for k, v in graph.graph.items()}
    )

    for node, attrs in graph.nodes(data=True):
        safe_graph.add_node(
            node,
            **{k: _gexf_safe(v) for k, v in attrs.items()},
        )

    for u, v, attrs in graph.edges(data=True):
        safe_graph.add_edge(
            u,
            v,
            **{k: _gexf_safe(vv) for k, vv in attrs.items()},
        )

    return safe_graph


def write_attack_graph_gexf(graph: nx.DiGraph, path: str) -> None:
    """Write a GEXF file after converting unsupported attribute types."""
    nx.write_gexf(_sanitize_graph_for_gexf(graph), path)


def build_attack_graph(events: pd.DataFrame) -> nx.DiGraph:
    """Build an entity/event graph from a metadata-rich event table."""
    required = {
        "event_id", "src_ip", "dst_ip", "attack_type", "protocol",
        "start_time", "end_time", "flow_count",
    }
    missing = required - set(events.columns)
    if missing:
        raise ValueError(f"Missing event columns: {sorted(missing)}")

    graph = nx.DiGraph()

    for _, event in events.iterrows():
        src = f"host:{event['src_ip']}"
        dst = f"host:{event['dst_ip']}"
        attack = f"attack:{event['attack_type']}"
        event_node = f"event:{event['event_id']}"

        graph.add_node(src, node_type="source", label=str(event["src_ip"]))
        graph.add_node(dst, node_type="target", label=str(event["dst_ip"]))
        graph.add_node(
            attack,
            node_type="attack_type",
            label=str(event["attack_type"]),
        )
        graph.add_node(
            event_node,
            node_type="event",
            label=str(event["event_id"]),
            protocol=str(event["protocol"]),
            start_time=_gexf_safe(event["start_time"]),
            end_time=_gexf_safe(event["end_time"]),
            flow_count=int(event["flow_count"]),
            mean_anomaly_score=_gexf_safe(event.get("mean_anomaly_score")),
        )

        graph.add_edge(src, event_node, relation="initiates")
        graph.add_edge(event_node, attack, relation="classified_as")
        graph.add_edge(event_node, dst, relation="targets")

        if "incident_id" in event and pd.notna(event["incident_id"]):
            incident_node = f"incident:{event['incident_id']}"
            graph.add_node(
                incident_node,
                node_type="incident",
                label=str(event["incident_id"]),
            )
            graph.add_edge(
                incident_node,
                event_node,
                relation="contains",
            )

    return graph


def add_sequence_edges(
    graph: nx.DiGraph,
    events: pd.DataFrame,
    *,
    max_gap_seconds: int = 300,
    require_shared_source: bool = True,
    require_shared_target: bool = True,
) -> nx.DiGraph:
    """Add temporal edges only between consecutive related events."""

    if events.empty:
        return graph

    work = events.copy()
    work["start_time"] = pd.to_datetime(
        work["start_time"], errors="coerce", utc=True
    )
    work["end_time"] = pd.to_datetime(
        work["end_time"], errors="coerce", utc=True
    )

    if work[["start_time", "end_time"]].isna().any().any():
        raise ValueError("Sequence edges require valid event timestamps.")

    work = work.sort_values("start_time").reset_index(drop=True)

    for i in range(len(work) - 1):
        left = work.iloc[i]
        right = work.iloc[i + 1]

        gap = (right["start_time"] - left["end_time"]).total_seconds()

        shared_source = left["src_ip"] == right["src_ip"]
        shared_target = left["dst_ip"] == right["dst_ip"]

        related = (
            gap >= 0
            and gap <= max_gap_seconds
            and (shared_source if require_shared_source else True)
            and (shared_target if require_shared_target else True)
        )

        if related and left["event_id"] != right["event_id"]:
            graph.add_edge(
                f"event:{left['event_id']}",
                f"event:{right['event_id']}",
                relation="precedes",
                gap_seconds=float(gap),
            )

    return graph
