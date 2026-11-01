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


def build_attack_graph(
    events: pd.DataFrame,
    correlations: pd.DataFrame | None = None,
) -> nx.DiGraph:
    """Compatibility adapter to the canonical SOC attack-graph constructor.

    Event correlation is owned by EventCorrelationAgent in soc_investigation;
    this module must not maintain a second graph schema or edge algorithm.
    """
    from .soc_investigation import build_soc_graph

    return build_soc_graph(events, correlations=correlations)


def add_sequence_edges(
    graph: nx.DiGraph,
    events: pd.DataFrame,
    *,
    max_gap_seconds: int = 300,
    require_shared_source: bool = True,
    require_shared_target: bool = True,
) -> nx.DiGraph:
    """Compatibility adapter that applies canonical event-correlation edges.

    The shared-source/shared-target switches retain the historical API. When
    both are true, only event pairs with both relationships are added. The
    canonical pipeline does not call this adapter; it passes the full
    correlation table directly into build_attack_graph.
    """
    if events.empty:
        return graph
    from .soc_investigation import EventCorrelationAgent

    correlations = EventCorrelationAgent(
        events,
        max_gap_seconds=max_gap_seconds,
    ).correlate()
    pair_relations: dict[tuple[str, str], list[dict]] = {}
    for _, row in correlations.iterrows():
        pair = (str(row["from_event"]), str(row["to_event"]))
        pair_relations.setdefault(pair, []).append(row.to_dict())

    for (source_id, target_id), rows in pair_relations.items():
        relations = {str(row["relation"]) for row in rows}
        has_source = "same_source_temporal" in relations
        has_target = "same_target_temporal" in relations
        if require_shared_source and not has_source:
            continue
        if require_shared_target and not has_target:
            continue
        source = f"event:{source_id}"
        target = f"event:{target_id}"
        if source not in graph or target not in graph:
            raise ValueError(
                f"Graph is missing event nodes required by correlation: {source}, {target}"
            )
        for row in rows:
            relation = str(row["relation"])
            attrs = {
                key: row.get(key)
                for key in (
                    "gap_seconds",
                    "overlap_seconds",
                    "shared_entity",
                    "pivot_host",
                )
                if row.get(key) is not None and not pd.isna(row.get(key))
            }
            if graph.has_edge(source, target):
                existing = set(
                    str(graph[source][target].get("relations", "")).split("|")
                )
                existing.add(relation)
                graph[source][target]["relations"] = "|".join(sorted(x for x in existing if x))
                graph[source][target]["relation"] = graph[source][target]["relations"]
                for key, value in attrs.items():
                    graph[source][target].setdefault(key, value)
            else:
                graph.add_edge(
                    source,
                    target,
                    relation=relation,
                    relations=relation,
                    **attrs,
                )
    return graph
