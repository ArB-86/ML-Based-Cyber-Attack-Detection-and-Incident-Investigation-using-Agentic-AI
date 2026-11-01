"""Evidence-first SOC investigation: graph analysis, threat hypotheses and triage."""
from __future__ import annotations

from bisect import bisect_right
import json
import math
from pathlib import Path
from typing import Any

import networkx as nx
import pandas as pd

from .event_builder import normalize_columns


def _bool_series(values: pd.Series) -> pd.Series:
    if pd.api.types.is_bool_dtype(values):
        return values.fillna(False)
    if pd.api.types.is_numeric_dtype(values):
        return pd.to_numeric(values, errors="coerce").fillna(0).ne(0)
    return values.astype(str).str.strip().str.lower().isin({"true", "1", "yes", "y"})


def _tokens(values: pd.Series) -> set[str]:
    found: set[str] = set()
    for value in values.fillna("").astype(str):
        found.update(part.strip().upper() for part in value.replace(",", ";").split(";") if part.strip())
    return found


def build_soc_events(
    alert_flows: pd.DataFrame,
    event_gap_seconds: int = 60,
    max_flows_per_event: int = 5000,
    use_ports_in_key: bool = False,
) -> pd.DataFrame:
    """Aggregate detector alerts into canonical, metadata-preserving events.

    Ground-truth labels are never read. Grouping uses endpoint pair, protocol,
    optional port pair, temporal gap and a maximum event size. Original input
    row identifiers and detector provenance are retained for traceability.
    """
    columns = [
        "event_id", "start_time", "end_time", "duration_seconds",
        "src_ip", "dst_ip", "protocol", "attack_type", "flow_count",
        "mean_anomaly_score", "min_anomaly_score", "src_ports", "dst_ports",
        "unique_src_ports", "unique_dst_ports", "detection_reasons",
        "alert_sources", "flow_row_ids",
    ]
    if event_gap_seconds < 0 or max_flows_per_event < 1:
        raise ValueError("Event gap must be non-negative and max_flows_per_event must be positive.")
    if alert_flows.empty:
        return pd.DataFrame(columns=columns)

    work = normalize_columns(alert_flows).copy()
    work.columns = [str(column).strip().lower() for column in work.columns]
    required = {"timestamp", "src_ip", "dst_ip", "protocol", "alert"}
    missing = required - set(work.columns)
    if missing:
        raise ValueError(f"SOC event builder requires columns: {sorted(missing)}")

    work["_flow_row_id"] = work.index.astype(str)
    work = work.reset_index(drop=True)
    work["timestamp"] = pd.to_datetime(
        work["timestamp"], errors="coerce", utc=True, format="mixed"
    )
    if work["timestamp"].isna().any():
        raise ValueError("SOC event builder received invalid timestamps.")
    work["alert"] = _bool_series(work["alert"])
    work = work.loc[work["alert"]].copy()
    if work.empty:
        return pd.DataFrame(columns=columns)

    work["src_ip"] = work["src_ip"].astype(str).str.strip()
    work["dst_ip"] = work["dst_ip"].astype(str).str.strip()
    work["protocol"] = work["protocol"].astype(str).str.strip()
    if "src_port" not in work.columns:
        work["src_port"] = pd.NA
    if "dst_port" not in work.columns:
        work["dst_port"] = pd.NA
    if "anomaly_score" not in work.columns:
        work["anomaly_score"] = pd.NA
    if "detection_reasons" not in work.columns:
        work["detection_reasons"] = "UNSPECIFIED_DETECTION"
    if "alert_sources" not in work.columns:
        work["alert_sources"] = "UNSPECIFIED_ALERT_SOURCE"

    work = work.sort_values("timestamp", kind="stable")
    group_columns = ["src_ip", "dst_ip", "protocol"]
    if use_ports_in_key:
        group_columns.extend(["src_port", "dst_port"])

    groups: list[pd.DataFrame] = []
    for _, group in work.groupby(group_columns, dropna=False, sort=True):
        group = group.sort_values("timestamp", kind="stable")
        indices: list[int] = []
        previous = None
        for index, row in group.iterrows():
            timestamp = row["timestamp"]
            gap = None if previous is None else (timestamp - previous).total_seconds()
            size_limit_reached = len(indices) >= max_flows_per_event
            if indices and (gap > event_gap_seconds or size_limit_reached):
                groups.append(group.loc[indices].copy())
                indices = []
            indices.append(index)
            previous = timestamp
        if indices:
            groups.append(group.loc[indices].copy())

    groups.sort(
        key=lambda rows: (
            rows["timestamp"].min(),
            str(rows["src_ip"].iloc[0]),
            str(rows["dst_ip"].iloc[0]),
            str(rows["protocol"].iloc[0]),
        )
    )

    records: list[dict[str, Any]] = []
    for number, rows in enumerate(groups, start=1):
        reasons = _tokens(rows["detection_reasons"]) or {"UNSPECIFIED_DETECTION"}
        sources = _tokens(rows["alert_sources"])
        scores = pd.to_numeric(rows["anomaly_score"], errors="coerce")
        src_port_values = pd.to_numeric(rows["src_port"], errors="coerce").dropna()
        dst_port_values = pd.to_numeric(rows["dst_port"], errors="coerce").dropna()
        src_ports = sorted({int(port) for port in src_port_values if 0 <= int(port) <= 65535})
        dst_ports = sorted({int(port) for port in dst_port_values if 0 <= int(port) <= 65535})
        start, end = rows["timestamp"].min(), rows["timestamp"].max()
        records.append({
            "event_id": f"EVT-{number:06d}",
            "start_time": start,
            "end_time": end,
            "duration_seconds": float((end - start).total_seconds()),
            "src_ip": str(rows["src_ip"].iloc[0]),
            "dst_ip": str(rows["dst_ip"].iloc[0]),
            "protocol": str(rows["protocol"].iloc[0]),
            "attack_type": ", ".join(sorted(reasons)),
            "flow_count": int(len(rows)),
            "mean_anomaly_score": None if scores.notna().sum() == 0 else float(scores.mean()),
            "min_anomaly_score": None if scores.notna().sum() == 0 else float(scores.min()),
            "src_ports": src_ports,
            "dst_ports": dst_ports,
            "unique_src_ports": len(src_ports),
            "unique_dst_ports": len(dst_ports),
            "detection_reasons": ";".join(sorted(reasons)),
            "alert_sources": ";".join(sorted(sources)),
            "flow_row_ids": [str(value) for value in rows["_flow_row_id"].tolist()],
        })
    return pd.DataFrame(records, columns=columns)

def _add_edge(graph: nx.DiGraph, source: str, target: str, relation: str, **attrs: Any) -> None:
    if source == target:
        return
    if graph.has_edge(source, target):
        existing = set(str(graph[source][target].get("relations", "")).split("|"))
        existing.add(relation)
        graph[source][target]["relations"] = "|".join(sorted(x for x in existing if x))
        graph[source][target]["relation"] = graph[source][target]["relations"]
        for key, value in attrs.items():
            if value is not None:
                graph[source][target].setdefault(key, value)
    else:
        graph.add_edge(source, target, relation=relation, relations=relation,
                       **{key: value for key, value in attrs.items() if value is not None})


CORRELATION_COLUMNS = [
    "from_event", "to_event", "relation", "gap_seconds",
    "overlap_seconds", "shared_entity", "pivot_host",
]


class EventCorrelationAgent:
    """Correlate events by shared network entities and temporal relationships."""

    def __init__(self, events: pd.DataFrame, max_gap_seconds: int = 300):
        self.events = events.copy()
        self.max_gap_seconds = max_gap_seconds

    def correlate(self) -> pd.DataFrame:
        if self.max_gap_seconds < 0:
            raise ValueError("max_gap_seconds must be non-negative.")
        if self.events.empty:
            return pd.DataFrame(columns=CORRELATION_COLUMNS)

        work = self.events.copy().reset_index(drop=True)
        for column in ("start_time", "end_time"):
            work[column] = pd.to_datetime(
                work[column], errors="coerce", utc=True, format="mixed"
            )
        required = {"event_id", "start_time", "end_time", "src_ip", "dst_ip"}
        missing = required - set(work.columns)
        if missing:
            raise ValueError(f"Event correlation is missing columns: {sorted(missing)}")
        if work[["start_time", "end_time"]].isna().any().any():
            raise ValueError("Event correlation requires valid event timestamps.")

        entity_events: dict[tuple[str, str], list[pd.Series]] = {}
        received: dict[str, list[tuple[pd.Timestamp, str]]] = {}
        initiated: dict[str, list[tuple[pd.Timestamp, str]]] = {}

        for _, event in work.iterrows():
            event_id = str(event["event_id"])
            src, dst = str(event["src_ip"]), str(event["dst_ip"])
            entity_events.setdefault(("source", src), []).append(event)
            entity_events.setdefault(("target", dst), []).append(event)
            received.setdefault(dst, []).append((event["end_time"], event_id))
            initiated.setdefault(src, []).append((event["start_time"], event_id))

            ports = event.get("dst_ports", [])
            if isinstance(ports, str):
                try:
                    import ast
                    ports = ast.literal_eval(ports)
                except (SyntaxError, ValueError):
                    ports = []
            if not isinstance(ports, (list, tuple, set)):
                ports = []
            for port in sorted({
                int(value) for value in ports
                if str(value).isdigit() and 0 <= int(value) <= 65535
            }):
                service = f"{str(event.get('protocol', 'unknown')).lower()}/{port}"
                entity_events.setdefault(("service", service), []).append(event)

        records: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()

        def add(
            previous_id: str,
            current_id: str,
            relation: str,
            previous_end: pd.Timestamp,
            current_start: pd.Timestamp,
            shared_entity: str | None = None,
            pivot_host: str | None = None,
        ) -> None:
            if previous_id == current_id:
                return
            raw_gap = (current_start - previous_end).total_seconds()
            gap = max(0.0, raw_gap)
            overlap = max(0.0, -raw_gap)
            if gap > self.max_gap_seconds:
                return
            key = (previous_id, current_id, relation)
            if key in seen:
                return
            seen.add(key)
            records.append({
                "from_event": previous_id,
                "to_event": current_id,
                "relation": relation,
                "gap_seconds": float(gap),
                "overlap_seconds": float(overlap),
                "shared_entity": shared_entity,
                "pivot_host": pivot_host,
            })

        # Consecutive relationships for each entity avoid a quadratic all-pairs
        # join while allowing source, target and service links independently.
        for (kind, entity), rows in entity_events.items():
            rows.sort(key=lambda row: (row["start_time"], row["end_time"], str(row["event_id"])))
            for previous, current in zip(rows, rows[1:]):
                add(
                    str(previous["event_id"]),
                    str(current["event_id"]),
                    f"same_{kind}_temporal",
                    previous["end_time"],
                    current["start_time"],
                    shared_entity=entity,
                )

        # Target-to-source pivot: an asset that was targeted, then later
        # initiated another connection. Retain exact event IDs and pivot host.
        for host, source_events in initiated.items():
            prior = sorted(received.get(host, []), key=lambda item: item[0])
            prior_times = [item[0] for item in prior]
            for start_time, source_event_id in source_events:
                position = bisect_right(prior_times, start_time) - 1
                if position < 0:
                    continue
                end_time, target_event_id = prior[position]
                if target_event_id == source_event_id:
                    continue
                gap = (start_time - end_time).total_seconds()
                if 0 <= gap <= self.max_gap_seconds:
                    add(
                        target_event_id,
                        source_event_id,
                        "host_pivot",
                        end_time,
                        start_time,
                        pivot_host=host,
                    )

        if not records:
            return pd.DataFrame(columns=CORRELATION_COLUMNS)
        result = pd.DataFrame(records, columns=CORRELATION_COLUMNS)
        return result.sort_values(
            ["from_event", "to_event", "relation"],
            kind="stable",
        ).reset_index(drop=True)


def build_soc_graph(
    events: pd.DataFrame,
    correlations: pd.DataFrame | None = None,
) -> nx.DiGraph:
    """Build the typed attack graph from events and explicit correlation edges.

    Correlation is deliberately a separate preceding stage. If no correlation
    table is supplied, it is generated through EventCorrelationAgent for
    compatibility with existing callers.
    """
    graph = nx.DiGraph()
    graph.graph["schema"] = "soc-investigation-graph-v3"
    graph.graph["ground_truth_labels_used"] = False
    if correlations is None:
        correlations = EventCorrelationAgent(events).correlate()
    graph.graph["correlation_count"] = int(len(correlations))

    if events.empty:
        return graph

    work = events.copy()
    for column in ("start_time", "end_time"):
        work[column] = pd.to_datetime(work[column], errors="coerce", utc=True, format="mixed")
    if work[["start_time", "end_time"]].isna().any().any():
        raise ValueError("Graph construction requires valid event timestamps.")

    for _, event in work.iterrows():
        eid, src, dst = str(event["event_id"]), str(event["src_ip"]), str(event["dst_ip"])
        enode, snode, dnode = f"event:{eid}", f"host:{src}", f"host:{dst}"
        graph.add_node(snode, node_type="host", label=src, ip=src)
        graph.add_node(dnode, node_type="host", label=dst, ip=dst)

        event_attrs = {
            "node_type": "event",
            "event_id": eid,
            "label": eid,
            "start_time": event["start_time"].isoformat(),
            "end_time": event["end_time"].isoformat(),
            "protocol": str(event.get("protocol", "unknown")),
            "flow_count": int(event.get("flow_count", 0)),
            "detection_reasons": str(event.get("detection_reasons", "")),
            "alert_sources": str(event.get("alert_sources", "")),
        }
        score = event.get("mean_anomaly_score")
        if score is not None and pd.notna(score):
            event_attrs["mean_anomaly_score"] = float(score)
        graph.add_node(enode, **event_attrs)
        _add_edge(graph, snode, enode, "originates")
        _add_edge(graph, enode, dnode, "targets")

        ports = event.get("dst_ports", [])
        if isinstance(ports, str):
            try:
                import ast
                ports = ast.literal_eval(ports)
            except (SyntaxError, ValueError):
                ports = []
        if not isinstance(ports, (list, tuple, set)):
            ports = []
        for port in sorted({
            int(value) for value in ports
            if str(value).isdigit() and 0 <= int(value) <= 65535
        }):
            protocol = str(event.get("protocol", "unknown")).lower()
            service = f"service:{protocol}/{port}"
            graph.add_node(service, node_type="service", label=f"{protocol}/{port}", port=port)
            _add_edge(graph, enode, service, "touches_service")

        for reason in str(event.get("detection_reasons", "")).split(";"):
            reason = reason.strip()
            if reason:
                detection = f"detection:{reason}"
                graph.add_node(detection, node_type="detection", label=reason)
                _add_edge(graph, enode, detection, "triggered_by")

    for _, edge in correlations.iterrows():
        previous_id, current_id = str(edge["from_event"]), str(edge["to_event"])
        source, target = f"event:{previous_id}", f"event:{current_id}"
        if source not in graph or target not in graph:
            raise ValueError(
                f"Correlation references unknown event IDs: {previous_id}, {current_id}"
            )
        attrs = {
            "gap_seconds": float(edge["gap_seconds"]),
            "overlap_seconds": float(edge.get("overlap_seconds", 0.0) or 0.0),
            "shared_entity": edge.get("shared_entity"),
            "pivot_host": edge.get("pivot_host"),
        }
        _add_edge(graph, source, target, str(edge["relation"]), **attrs)
    return graph

class GraphAnalystAgent:
    """Compute graph topology, event chains, host roles and destination concentration."""
    def __init__(self, graph: nx.DiGraph):
        self.graph = graph
        self.event_graph = nx.Graph()
        for node, attrs in graph.nodes(data=True):
            if attrs.get("node_type") == "event":
                self.event_graph.add_node(node)
        for source, target, attrs in graph.edges(data=True):
            if source in self.event_graph and target in self.event_graph:
                self.event_graph.add_edge(source, target, **attrs)

    def analyse(self, component: set[str], rows: pd.DataFrame) -> dict[str, Any]:
        src_fanout = rows.groupby("src_ip")["dst_ip"].nunique().to_dict()
        dst_fanin = rows.groupby("dst_ip")["src_ip"].nunique().to_dict()
        dst_ports = sorted({int(p) for ports in rows.get("dst_ports", pd.Series(dtype=object))
                            if isinstance(ports, (list, tuple, set)) for p in ports if str(p).isdigit()})
        pivots, links = set(), []
        for source, target, attrs in self.graph.edges(data=True):
            if source not in component or target not in component:
                continue
            relation = str(attrs.get("relations", attrs.get("relation", "")))
            if "host_pivot" in relation and attrs.get("pivot_host"):
                pivots.add(str(attrs["pivot_host"]))
            links.append({
                "from_event": source.removeprefix("event:"),
                "to_event": target.removeprefix("event:"),
                "relation": relation,
                "gap_seconds": attrs.get("gap_seconds"),
                "pivot_host": attrs.get("pivot_host"),
            })
        component_graph = self.event_graph.subgraph(component).copy()
        relation_counts: dict[str, int] = {}
        for _, _, attrs in component_graph.edges(data=True):
            for relation in str(attrs.get("relations", attrs.get("relation", ""))).split("|"):
                if relation:
                    relation_counts[relation] = relation_counts.get(relation, 0) + 1
        degree_values = nx.degree_centrality(component_graph) if component_graph.number_of_nodes() > 1 else {
            node: 0.0 for node in component_graph.nodes()
        }
        if component_graph.number_of_nodes() > 2:
            betweenness_values = nx.betweenness_centrality(
                component_graph,
                k=min(100, component_graph.number_of_nodes()),
                seed=42,
            )
        else:
            betweenness_values = {node: 0.0 for node in component_graph.nodes()}
        top_central_events = [
            {
                "event_id": node.removeprefix("event:"),
                "degree_centrality": round(float(degree_values.get(node, 0.0)), 4),
                "betweenness_centrality": round(float(betweenness_values.get(node, 0.0)), 4),
            }
            for node in sorted(
                component_graph.nodes(),
                key=lambda item: (
                    -degree_values.get(item, 0.0),
                    -betweenness_values.get(item, 0.0),
                    item,
                ),
            )[:5]
        ]
        return {
            "event_count": int(len(rows)),
            "graph_event_links": int(component_graph.number_of_edges()),
            "graph_density": round(float(nx.density(component_graph)), 4) if component_graph.number_of_nodes() > 1 else 0.0,
            "edge_relation_counts": dict(sorted(relation_counts.items())),
            "top_central_events": top_central_events,
            "unique_sources": int(rows["src_ip"].nunique()),
            "unique_targets": int(rows["dst_ip"].nunique()),
            "unique_services": len(dst_ports),
            "destination_ports": dst_ports,
            "max_source_fanout": int(max(src_fanout.values(), default=0)),
            "max_target_fanin": int(max(dst_fanin.values(), default=0)),
            "top_sources": [
                {
                    "ip": str(ip),
                    "unique_targets": int(n),
                    "event_ids": rows.loc[rows["src_ip"].eq(ip), "event_id"].astype(str).tolist(),
                }
                for ip, n in sorted(src_fanout.items(), key=lambda x: (-x[1], str(x[0])))[:5]
            ],
            "top_targets": [
                {
                    "ip": str(ip),
                    "unique_sources": int(n),
                    "event_ids": rows.loc[rows["dst_ip"].eq(ip), "event_id"].astype(str).tolist(),
                }
                for ip, n in sorted(dst_fanin.items(), key=lambda x: (-x[1], str(x[0])))[:5]
            ],
            "pivot_hosts": sorted(pivots),
            "chain_edges": sorted(links, key=lambda x: (x["from_event"], x["to_event"])),
            "assets": sorted(set(rows["src_ip"].astype(str)) | set(rows["dst_ip"].astype(str))),
        }


class ThreatHuntingAgent:
    """Map only observable behaviours to ATT&CK candidate techniques."""
    @staticmethod
    def analyse(rows: pd.DataFrame, graph_data: dict[str, Any]) -> list[dict[str, str]]:
        reasons = _tokens(rows.get("detection_reasons", pd.Series(dtype=object)))
        hypotheses = []
        event_ids = rows["event_id"].astype(str)
        reasons_by_event = rows.get(
            "detection_reasons", pd.Series("", index=rows.index)
        ).fillna("").astype(str)
        scan_ids = event_ids[
            reasons_by_event.str.contains(
                r"PORT_SCAN|HORIZONTAL_SCAN|HIGH_SOURCE_FANOUT", regex=True
            )
        ].tolist()
        dos_ids = event_ids[
            reasons_by_event.str.contains("DISTRIBUTED_DOS_PATTERN", regex=False)
        ].tolist()
        brute_ids = event_ids[
            reasons_by_event.str.contains("BRUTE_FORCE_PATTERN", regex=False)
        ].tolist()
        pivot_ids = sorted({
            event_id
            for edge in graph_data["chain_edges"]
            if "host_pivot" in edge["relation"]
            for event_id in (edge["from_event"], edge["to_event"])
        })
        if reasons.intersection({"PORT_SCAN", "HORIZONTAL_SCAN", "HIGH_SOURCE_FANOUT"}):
            hypotheses.append({
                "technique_id": "T1046", "technique": "Network Service Discovery",
                "confidence": "medium",
                "evidence": "A source probed multiple destination services or hosts in a bounded time window.",
                "evidence_event_ids": scan_ids,
                "caveat": "Check authorised scanner schedules, firewall and IDS telemetry.",
            })
        if "DISTRIBUTED_DOS_PATTERN" in reasons or graph_data["max_target_fanin"] >= 15:
            hypotheses.append({
                "technique_id": "T1498", "technique": "Network Denial of Service",
                "confidence": "medium",
                "evidence": "A destination received flows from many distinct sources in a bounded interval.",
                "evidence_event_ids": dos_ids or [
                    event_id
                    for lead in graph_data["top_targets"][:1]
                    for event_id in lead["event_ids"]
                ],
                "caveat": "Flow metadata alone does not establish service impact or malicious intent.",
            })
        if "BRUTE_FORCE_PATTERN" in reasons:
            hypotheses.append({
                "technique_id": "T1110", "technique": "Brute Force",
                "confidence": "medium",
                "evidence": "Repeated flows targeted an authentication service from one source to one destination.",
                "evidence_event_ids": brute_ids,
                "caveat": "Authentication success/failure logs are required to confirm credential guessing.",
            })
        if graph_data["pivot_hosts"] and {22, 445, 3389, 5985, 5986, 5900}.intersection(graph_data["destination_ports"]):
            hypotheses.append({
                "technique_id": "T1021", "technique": "Remote Services",
                "confidence": "low",
                "evidence": "A host was targeted and later initiated another related flow involving a remote-access port.",
                "evidence_event_ids": pivot_ids,
                "caveat": "A pivot is an investigation lead, not proof of lateral movement.",
            })
        return hypotheses


class IncidentTriageAgent:
    """Rank incidents with inspectable evidence-derived priority components."""

    @staticmethod
    def score(
        rows: pd.DataFrame,
        graph_data: dict[str, Any],
        hypotheses: list[dict[str, str]],
        anomaly_strength: float | None,
    ) -> dict[str, Any]:
        reasons = _tokens(rows.get("detection_reasons", pd.Series(dtype=object)))
        behavioural = reasons - {"ISOLATION_FOREST_ANOMALY", "ANOMALY"}
        components = {
            "behavioural_rule_diversity": min(1.0, len(behavioural) / 3.0),
            "event_persistence": min(
                1.0,
                math.log1p(len(rows)) / math.log1p(10),
            ),
            "source_fanout": min(1.0, graph_data["max_source_fanout"] / 20.0),
            "destination_convergence": min(1.0, graph_data["max_target_fanin"] / 20.0),
            "service_diversity": min(1.0, graph_data["unique_services"] / 20.0),
        }
        weights = {
            "behavioural_rule_diversity": 30.0,
            "event_persistence": 20.0,
            "source_fanout": 20.0,
            "destination_convergence": 15.0,
            "service_diversity": 10.0,
        }
        if anomaly_strength is not None:
            components["isolation_forest_support"] = max(
                0.0, min(1.0, float(anomaly_strength))
            )
            weights["isolation_forest_support"] = 5.0

        total_weight = sum(weights.values())
        contributions = {
            name: round(weights[name] * components[name] / total_weight * 100.0, 2)
            for name in components
        }
        risk = round(sum(contributions.values()), 1)
        severity = (
            "CRITICAL" if risk >= 80
            else "HIGH" if risk >= 60
            else "MEDIUM" if risk >= 35
            else "LOW"
        )

        signal_count = int(bool(behavioural))
        signal_count += int(graph_data["graph_event_links"] > 0 or bool(graph_data["pivot_hosts"]))
        signal_count += int(anomaly_strength is not None)
        signal_count += int(len(hypotheses) > 1)
        confidence = (
            "HIGH" if signal_count >= 3 and len(rows) >= 4
            else "MEDIUM" if signal_count >= 2 or len(rows) >= 3
            else "LOW"
        )
        return {
            "risk_score": risk,
            "severity": severity,
            "confidence": confidence,
            "independent_signal_count": signal_count,
            "components": {
                name: {
                    "normalised_value": round(float(components[name]), 4),
                    "weight_pct": weights[name],
                    "contribution_points": contributions[name],
                }
                for name in components
            },
            "scoring_note": (
                "Heuristic SOC triage priority, not a calibrated probability "
                "of compromise. Tune weights against analyst-labelled incidents."
            ),
        }


class IncidentFormationAgent:
    """Form candidate incidents from the explicit event-correlation table."""

    def __init__(self, events: pd.DataFrame, correlations: pd.DataFrame):
        self.events = events
        self.correlations = correlations

    def form(self) -> list[tuple[pd.Timestamp, set[str], pd.DataFrame]]:
        event_nodes = {f"event:{event_id}" for event_id in self.events["event_id"].astype(str)}
        correlated = nx.Graph()
        correlated.add_nodes_from(event_nodes)
        known_ids = {node.removeprefix("event:") for node in event_nodes}
        for _, edge in self.correlations.iterrows():
            source_id, target_id = str(edge["from_event"]), str(edge["to_event"])
            if source_id not in known_ids or target_id not in known_ids:
                raise ValueError(
                    f"Incident formation received an unknown event link: {source_id} -> {target_id}"
                )
            correlated.add_edge(f"event:{source_id}", f"event:{target_id}", **edge.to_dict())

        components = []
        for component in nx.connected_components(correlated):
            event_ids = {node.removeprefix("event:") for node in component}
            rows = self.events[self.events["event_id"].astype(str).isin(event_ids)].copy()
            if not rows.empty:
                components.append((rows["start_time"].min(), set(component), rows))
        components.sort(key=lambda item: item[0])
        return components


class SOCInvestigationOrchestrator:
    """Coordinate graph analyst, threat hunter and incident triage stages."""
    def __init__(
        self,
        events: pd.DataFrame,
        graph: nx.DiGraph,
        correlations: pd.DataFrame,
    ):
        self.events = events.copy().reset_index(drop=True)
        self.graph = graph
        self.correlations = correlations.copy()
        self.graph_agent = GraphAnalystAgent(graph)
        scores = pd.to_numeric(self.events.get("mean_anomaly_score", pd.Series(index=self.events.index, dtype=float)), errors="coerce")
        if scores.notna().any():
            strength = 1.0 - scores.rank(method="average", pct=True)
            self.anomaly_strength = dict(zip(self.events["event_id"].astype(str), strength.fillna(0.0)))
        else:
            self.anomaly_strength = {}

    def run(self) -> list[dict[str, Any]]:
        components = IncidentFormationAgent(
            self.events, self.correlations
        ).form()
        incidents = []
        for number, (_, component, rows) in enumerate(components, start=1):
            ids = sorted(rows["event_id"].astype(str).tolist())
            graph_data = self.graph_agent.analyse(component, rows)
            hypotheses = ThreatHuntingAgent.analyse(rows, graph_data)
            # A stored IF score is not an independent signal unless IF
            # actually fired an alert for this incident.
            model_was_triggered = "ISOLATION_FOREST" in _tokens(
                rows.get("alert_sources", pd.Series(dtype=object))
            )
            values = (
                [self.anomaly_strength[eid] for eid in ids if eid in self.anomaly_strength]
                if model_was_triggered else []
            )
            anomaly_strength = None if not values else float(sum(values) / len(values))
            triage = IncidentTriageAgent.score(rows, graph_data, hypotheses, anomaly_strength)
            reasons = sorted(_tokens(rows.get("detection_reasons", pd.Series(dtype=object))))
            start, end = rows["start_time"].min(), rows["end_time"].max()
            incident = {
                "incident_id": f"INC-{number:05d}",
                "title": self._title(reasons, graph_data),
                "status": "NEEDS_ANALYST_VALIDATION",
                "start_time": start.isoformat(),
                "end_time": end.isoformat(),
                "duration_seconds": round(max(0.0, (end - start).total_seconds()), 2),
                "event_ids": ids,
                "total_flows": int(rows["flow_count"].sum()),
                "detection_reasons": reasons,
                "graph_analysis": graph_data,
                "attack_hypotheses": hypotheses,
                "triage": triage,
                "timeline": [
                    {
                        "event_id": str(row["event_id"]), "timestamp": row["start_time"].isoformat(),
                        "end_time": row["end_time"].isoformat(), "source": str(row["src_ip"]),
                        "destination": str(row["dst_ip"]), "protocol": str(row["protocol"]),
                        "flows": int(row["flow_count"]), "ports": row.get("dst_ports", []),
                        "evidence": str(row.get("detection_reasons", "")),
                    }
                    for _, row in rows.sort_values(["start_time", "end_time"]).iterrows()
                ],
                "recommended_actions": self._actions(reasons, graph_data),
            }
            incident_node = f"incident:{incident['incident_id']}"
            self.graph.add_node(
                incident_node,
                node_type="incident",
                label=incident["incident_id"],
                title=incident["title"],
                status=incident["status"],
                risk_score=float(triage["risk_score"]),
                severity=triage["severity"],
                confidence=triage["confidence"],
                event_count=len(ids),
            )
            for event_id in ids:
                _add_edge(
                    self.graph,
                    incident_node,
                    f"event:{event_id}",
                    "contains",
                )
            incidents.append(incident)
        incidents.sort(key=lambda item: (item["triage"]["risk_score"], item["start_time"]), reverse=True)
        return incidents

    @staticmethod
    def _title(reasons: list[str], graph_data: dict[str, Any]) -> str:
        r = set(reasons)
        if "DISTRIBUTED_DOS_PATTERN" in r or graph_data["max_target_fanin"] >= 15:
            return "Distributed traffic surge against a shared destination"
        if "BRUTE_FORCE_PATTERN" in r:
            return "Repeated authentication-service activity"
        if r.intersection({"PORT_SCAN", "HORIZONTAL_SCAN", "HIGH_SOURCE_FANOUT"}):
            return "Network reconnaissance and service discovery pattern"
        if graph_data["pivot_hosts"]:
            return "Multi-stage host-to-host activity chain"
        if "ISOLATION_FOREST_ANOMALY" in r:
            return "Unusual network-flow activity requiring validation"
        return "Correlated network security events"

    @staticmethod
    def _actions(reasons: list[str], graph_data: dict[str, Any]) -> list[str]:
        r = set(reasons)
        actions = [
            "Validate source, destination, time window and asset ownership against firewall, IDS, DNS and endpoint telemetry.",
            "Preserve flow records and acquire packet-capture or EDR evidence for the incident window.",
        ]
        if "BRUTE_FORCE_PATTERN" in r:
            actions.append("Review authentication success/failure logs; rotate credentials only if account compromise is confirmed.")
        if "DISTRIBUTED_DOS_PATTERN" in r:
            actions.append("Check service availability and upstream traffic; coordinate rate limiting or DDoS mitigation if impact is confirmed.")
        if r.intersection({"PORT_SCAN", "HORIZONTAL_SCAN", "HIGH_SOURCE_FANOUT"}):
            actions.append("Determine whether the probing source is an authorised scanner or unauthorised reconnaissance host.")
        if graph_data["pivot_hosts"]:
            actions.append("Prioritise pivot-host review by correlating inbound/outbound sessions with identity and process telemetry.")
        if not r.intersection({"PORT_SCAN", "HORIZONTAL_SCAN", "HIGH_SOURCE_FANOUT", "DISTRIBUTED_DOS_PATTERN", "BRUTE_FORCE_PATTERN"}):
            actions.append("Do not assign an ATT&CK technique yet; gather endpoint, identity and application evidence first.")
        actions.append("Apply isolation or blocking only after analyst validation of evidence, ownership and business impact.")
        return actions




class IncidentEvidenceTools:
    """Read-only, evidence-scoped tools available to the investigation agent."""

    def __init__(self, incidents: list[dict[str, Any]], events: pd.DataFrame, graph: nx.DiGraph):
        self.incidents = {item["incident_id"]: item for item in incidents}
        self.events = {str(row["event_id"]): row.to_dict() for _, row in events.iterrows()}
        self.graph = graph

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        if incident_id not in self.incidents:
            raise KeyError(f"Unknown incident_id: {incident_id}")
        item = self.incidents[incident_id]
        return {
            "incident_id": item["incident_id"],
            "title": item["title"],
            "start_time": item["start_time"],
            "end_time": item["end_time"],
            "event_ids": list(item["event_ids"]),
            "detection_reasons": list(item["detection_reasons"]),
            "triage": dict(item["triage"]),
            "graph_analysis": dict(item["graph_analysis"]),
            "attack_hypotheses": list(item.get("attack_hypotheses", [])),
            "recommended_actions": list(item.get("recommended_actions", [])),
        }

    def get_event(self, event_id: str) -> dict[str, Any]:
        if event_id not in self.events:
            raise KeyError(f"Unknown event_id: {event_id}")
        row = self.events[event_id]
        return {
            key: (value.isoformat() if isinstance(value, pd.Timestamp) else value)
            for key, value in row.items()
        }

    def get_timeline(self, incident_id: str) -> list[dict[str, Any]]:
        incident = self.get_incident(incident_id)
        return [self.get_event(event_id) for event_id in incident["event_ids"]]

    def get_graph_neighborhood(self, incident_id: str) -> dict[str, Any]:
        incident = self.get_incident(incident_id)
        incident_node = f"incident:{incident_id}"
        if incident_node not in self.graph:
            raise KeyError(f"Incident graph node is missing: {incident_id}")
        neighborhood = []
        for event_node in self.graph.successors(incident_node):
            for neighbor in set(self.graph.predecessors(event_node)) | set(self.graph.successors(event_node)):
                if neighbor == incident_node:
                    continue
                attrs = self.graph.nodes[neighbor]
                neighborhood.append({
                    "node_id": str(neighbor),
                    "node_type": str(attrs.get("node_type", "unknown")),
                    "label": str(attrs.get("label", neighbor)),
                })
        edges = []
        members = {f"event:{event_id}" for event_id in incident["event_ids"]}
        for source, target, attrs in self.graph.edges(data=True):
            if source in members and target in members:
                edges.append({
                    "from": str(source),
                    "to": str(target),
                    "relation": str(attrs.get("relations", attrs.get("relation", ""))),
                    "gap_seconds": attrs.get("gap_seconds"),
                    "overlap_seconds": attrs.get("overlap_seconds"),
                    "pivot_host": attrs.get("pivot_host"),
                    "shared_entity": attrs.get("shared_entity"),
                })
        unique_nodes = {item["node_id"]: item for item in neighborhood}
        return {
            "incident_node": incident_node,
            "member_event_nodes": sorted(members),
            "related_nodes": sorted(unique_nodes.values(), key=lambda item: item["node_id"]),
            "event_edges": edges,
        }

    def get_detection_evidence(self, incident_id: str) -> dict[str, Any]:
        timeline = self.get_timeline(incident_id)
        by_reason: dict[str, list[str]] = {}
        by_source: dict[str, list[str]] = {}
        for event in timeline:
            event_id = str(event["event_id"])
            for reason in str(event.get("detection_reasons", "")).split(";"):
                reason = reason.strip()
                if reason:
                    by_reason.setdefault(reason, []).append(event_id)
            for source in str(event.get("alert_sources", "")).split(";"):
                source = source.strip()
                if source:
                    by_source.setdefault(source, []).append(event_id)
        return {
            "reason_to_event_ids": {key: sorted(set(value)) for key, value in sorted(by_reason.items())},
            "source_to_event_ids": {key: sorted(set(value)) for key, value in sorted(by_source.items())},
        }

    def get_host_activity(self, incident_id: str, host_ip: str) -> list[dict[str, Any]]:
        incident = self.get_incident(incident_id)
        return [
            self.get_event(event_id)
            for event_id in incident["event_ids"]
            if str(self.events[event_id].get("src_ip")) == host_ip
            or str(self.events[event_id].get("dst_ip")) == host_ip
        ]

    def get_service_activity(
        self,
        incident_id: str,
        destination_port: int,
        protocol: str | None = None,
    ) -> list[dict[str, Any]]:
        incident = self.get_incident(incident_id)
        if not 0 <= int(destination_port) <= 65535:
            raise ValueError("destination_port must be between 0 and 65535.")
        matches = []
        for event_id in incident["event_ids"]:
            event = self.events[event_id]
            ports = event.get("dst_ports", [])
            if isinstance(ports, str):
                try:
                    import ast
                    ports = ast.literal_eval(ports)
                except (SyntaxError, ValueError):
                    ports = []
            if not isinstance(ports, (list, tuple, set)):
                ports = []
            port_match = int(destination_port) in {
                int(port) for port in ports if str(port).isdigit()
            }
            protocol_match = protocol is None or str(event.get("protocol")) == str(protocol)
            if port_match and protocol_match:
                matches.append(self.get_event(event_id))
        return matches

    def get_correlated_events(
        self,
        incident_id: str,
        event_id: str | None = None,
        relation_contains: str | None = None,
    ) -> list[dict[str, Any]]:
        incident = self.get_incident(incident_id)
        member_nodes = {f"event:{value}" for value in incident["event_ids"]}
        if event_id is not None and event_id not in incident["event_ids"]:
            raise ValueError(f"event_id {event_id} does not belong to {incident_id}.")
        matches = []
        for source, target, attrs in self.graph.edges(data=True):
            if source not in member_nodes or target not in member_nodes:
                continue
            if event_id is not None and event_id not in {
                source.removeprefix("event:"), target.removeprefix("event:")
            }:
                continue
            relation = str(attrs.get("relations", attrs.get("relation", "")))
            if relation_contains and relation_contains not in relation:
                continue
            matches.append({
                "from_event": source.removeprefix("event:"),
                "to_event": target.removeprefix("event:"),
                "relation": relation,
                "gap_seconds": attrs.get("gap_seconds"),
                "overlap_seconds": attrs.get("overlap_seconds"),
                "shared_entity": attrs.get("shared_entity"),
                "pivot_host": attrs.get("pivot_host"),
            })
        return matches


class AgenticInvestigationAgent:
    """Execute a fixed evidence plan plus one bounded LLM-directed tool round.

    The optional reasoner receives evidence and a read-only tool catalogue. It
    may return plain text or a structured dictionary with tool_calls, findings
    and narrative. Only allowlisted tools and incident-scoped event IDs can be
    used. No arbitrary code or host actions are exposed to the model.
    """

    TOOL_CATALOG = [
        {
            "name": "get_event",
            "description": "Retrieve full flow and detector provenance for one incident event.",
            "arguments": {"event_id": "string"},
        },
        {
            "name": "get_host_activity",
            "description": "Retrieve events in this incident where a host is source or destination.",
            "arguments": {"incident_id": "string", "host_ip": "string"},
        },
        {
            "name": "get_service_activity",
            "description": "Retrieve events in this incident targeting a destination port.",
            "arguments": {"incident_id": "string", "destination_port": "integer", "protocol": "optional string"},
        },
        {
            "name": "get_correlated_events",
            "description": "Inspect exact event-to-event graph relationships and pivots.",
            "arguments": {"incident_id": "string", "event_id": "optional string", "relation_contains": "optional string"},
        },
    ]

    def __init__(self, tools: IncidentEvidenceTools, reasoner=None):
        self.tools = tools
        self.reasoner = reasoner
        self.available_tools = {
            "get_event": self.tools.get_event,
            "get_host_activity": self.tools.get_host_activity,
            "get_service_activity": self.tools.get_service_activity,
            "get_correlated_events": self.tools.get_correlated_events,
        }

    @staticmethod
    def _decode_reasoner_response(response: Any) -> dict[str, Any]:
        if isinstance(response, dict):
            return response
        if isinstance(response, str):
            stripped = response.strip()
            if stripped.startswith("{") and stripped.endswith("}"):
                try:
                    decoded = json.loads(stripped)
                    if isinstance(decoded, dict):
                        return decoded
                except json.JSONDecodeError:
                    pass
            return {"narrative": response}
        return {"narrative": str(response)}

    def _record_call(
        self,
        trace: list[dict[str, Any]],
        name: str,
        arguments: dict[str, Any],
        function,
    ) -> Any:
        try:
            result = function(**arguments)
            trace.append({
                "tool": name,
                "arguments": arguments,
                "status": "success",
                "result_summary": self._summarize(name, result),
                "evidence_refs": self._evidence_refs(name, result),
            })
            return result
        except Exception as exc:
            trace.append({
                "tool": name,
                "arguments": arguments,
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
                "evidence_refs": [],
            })
            return None

    def investigate(self, incident_id: str) -> dict[str, Any]:
        trace: list[dict[str, Any]] = []
        incident = self._record_call(
            trace, "get_incident", {"incident_id": incident_id}, self.tools.get_incident
        )
        timeline = self._record_call(
            trace, "get_timeline", {"incident_id": incident_id}, self.tools.get_timeline
        )
        graph = self._record_call(
            trace, "get_graph_neighborhood", {"incident_id": incident_id},
            self.tools.get_graph_neighborhood,
        )
        detections = self._record_call(
            trace, "get_detection_evidence", {"incident_id": incident_id},
            self.tools.get_detection_evidence,
        )
        if incident is None or timeline is None or graph is None or detections is None:
            return {
                "agent": "AgenticInvestigationAgent",
                "mode": "tool_assisted",
                "status": "partial_failure",
                "plan": ["retrieve_incident_context", "inspect_timeline", "inspect_graph", "inspect_detector_provenance"],
                "tool_calls": trace,
                "findings": [],
                "narrative": "Investigation could not retrieve all required evidence. Analyst review is required.",
            }

        claims: list[dict[str, Any]] = []
        for reason, event_ids in detections["reason_to_event_ids"].items():
            claims.append({
                "claim": f"Detection signal {reason} contributed to this candidate incident.",
                "evidence_event_ids": event_ids,
                "evidence_edges": [],
                "confidence": "high" if len(event_ids) >= 2 else "medium",
                "source": "detector_provenance",
            })

        analysis = incident["graph_analysis"]
        if analysis["max_source_fanout"] > 1 and analysis["top_sources"]:
            lead = analysis["top_sources"][0]
            claims.append({
                "claim": f"Source {lead['ip']} contacted {lead['unique_targets']} distinct destinations within this incident.",
                "evidence_event_ids": list(lead["event_ids"]),
                "evidence_edges": [],
                "confidence": "medium",
                "source": "graph_fanout",
            })
        if analysis["max_target_fanin"] > 1 and analysis["top_targets"]:
            lead = analysis["top_targets"][0]
            claims.append({
                "claim": f"Destination {lead['ip']} received traffic from {lead['unique_sources']} distinct sources.",
                "evidence_event_ids": list(lead["event_ids"]),
                "evidence_edges": [],
                "confidence": "medium",
                "source": "graph_convergence",
            })
        pivot_edges = [edge for edge in graph["event_edges"] if "host_pivot" in edge["relation"]]
        for edge in pivot_edges:
            claims.append({
                "claim": (
                    f"Host {edge['pivot_host']} was targeted and subsequently initiated "
                    "another correlated connection; this is a pivot lead."
                ),
                "evidence_event_ids": [
                    edge["from"].removeprefix("event:"),
                    edge["to"].removeprefix("event:"),
                ],
                "evidence_edges": [edge],
                "confidence": "medium",
                "source": "host_pivot",
            })

        narrative = (
            f"{incident['title']}. The candidate contains {len(timeline)} correlated events "
            f"over {incident['start_time']} to {incident['end_time']}. "
            f"Observed detection signals: {', '.join(incident['detection_reasons']) or 'none recorded'}. "
            f"Graph evidence contains {len(graph['event_edges'])} event-to-event relationships. "
            "Treat this as a candidate incident pending validation against endpoint, identity and service telemetry."
        )
        model_findings: list[dict[str, Any]] = []
        model_response: dict[str, Any] = {}

        if self.reasoner is not None:
            first_response = self._decode_reasoner_response(self.reasoner({
                "task": (
                    "Act as a SOC analyst. Inspect the supplied evidence, identify what is "
                    "still unknown, and request only relevant read-only tools. Do not assert "
                    "compromise from flow metadata alone. Return JSON with tool_calls (max 5), "
                    "preliminary_findings and narrative."
                ),
                "incident": incident,
                "timeline": timeline,
                "graph": graph,
                "detections": detections,
                "deterministic_findings": claims,
                "tool_catalog": self.TOOL_CATALOG,
                "response_contract": {
                    "tool_calls": [{"name": "get_event|get_host_activity|get_service_activity|get_correlated_events", "arguments": {}}],
                    "preliminary_findings": [{"claim": "string", "evidence_event_ids": ["event id"], "confidence": "low|medium|high"}],
                    "narrative": "string",
                },
            }))
            model_response = first_response
            requested_tools = first_response.get("tool_calls", [])
            if not isinstance(requested_tools, list):
                requested_tools = []

            tool_results = []
            allowed_event_ids = set(incident["event_ids"])
            for request in requested_tools[:5]:
                if not isinstance(request, dict):
                    continue
                name = request.get("name", request.get("tool"))
                arguments = request.get("arguments", {})
                if name not in self.available_tools or not isinstance(arguments, dict):
                    trace.append({
                        "tool": str(name),
                        "status": "rejected",
                        "error": "Tool is not allowlisted or arguments are invalid.",
                        "evidence_refs": [],
                    })
                    continue
                arguments = dict(arguments)
                if name == "get_event":
                    requested_id = str(arguments.get("event_id", ""))
                    if requested_id not in allowed_event_ids:
                        trace.append({
                            "tool": name,
                            "arguments": arguments,
                            "status": "rejected",
                            "error": "Event is outside this incident's scope.",
                            "evidence_refs": [],
                        })
                        continue
                if name != "get_event":
                    arguments.setdefault("incident_id", incident_id)
                result = self._record_call(trace, name, arguments, self.available_tools[name])
                if result is not None:
                    tool_results.append({"tool": name, "arguments": arguments, "result": result})

            if tool_results:
                model_response = self._decode_reasoner_response(self.reasoner({
                    "task": (
                        "Complete the SOC investigation using only this evidence. Return a concise "
                        "incident explanation, findings with exact event IDs, uncertainty/caveats, "
                        "and recommended analyst actions. Do not invent users, process execution, "
                        "successful logins, exfiltration or business impact."
                    ),
                    "incident": incident,
                    "initial_evidence": {"timeline": timeline, "graph": graph, "detections": detections},
                    "deterministic_findings": claims,
                    "additional_tool_results": tool_results,
                }))

            if model_response.get("narrative"):
                narrative = str(model_response["narrative"])
            preliminary = model_response.get(
                "findings", model_response.get("preliminary_findings", [])
            )
            if isinstance(preliminary, list):
                for finding in preliminary:
                    if not isinstance(finding, dict):
                        continue
                    event_refs = [str(value) for value in finding.get("evidence_event_ids", [])]
                    if event_refs and set(event_refs).issubset(allowed_event_ids):
                        model_findings.append({
                            "claim": str(finding.get("claim", finding.get("finding", ""))),
                            "evidence_event_ids": event_refs,
                            "evidence_edges": [],
                            "confidence": str(finding.get("confidence", "low")).lower(),
                            "source": "llm_evidence_validated",
                        })
                    else:
                        trace.append({
                            "tool": "validate_model_finding",
                            "status": "rejected",
                            "error": "Finding lacks valid event references or cites events outside this incident.",
                            "evidence_refs": [],
                        })

        all_findings = claims + model_findings
        return {
            "agent": "AgenticInvestigationAgent",
            "mode": "tool_assisted_llm" if self.reasoner is not None else "tool_assisted_deterministic",
            "status": "completed",
            "plan": [
                "retrieve_incident_context",
                "inspect_chronological_event_timeline",
                "inspect_correlated_graph_neighborhood",
                "cross_check_detection_provenance",
                "select_additional_read_only_tools",
                "validate_finding_event_references",
                "synthesise_evidence_linked_findings",
            ],
            "tool_calls": trace,
            "findings": all_findings,
            "model_findings_accepted": len(model_findings),
            "model_findings_rejected": sum(
                call.get("tool") == "validate_model_finding" for call in trace
            ),
            "attack_hypotheses": incident.get("attack_hypotheses", []),
            "recommended_actions": list(incident.get("recommended_actions", [])),
            "narrative": narrative,
        }

    @staticmethod
    def _summarize(name: str, result: Any) -> dict[str, Any]:
        if name == "get_event" and isinstance(result, dict):
            return {
                "event_id": result.get("event_id"),
                "source": result.get("src_ip"),
                "destination": result.get("dst_ip"),
                "detection_reasons": result.get("detection_reasons"),
            }
        if isinstance(result, list):
            return {"record_count": len(result)}
        if name == "get_graph_neighborhood":
            return {
                "event_edge_count": len(result["event_edges"]),
                "related_node_count": len(result["related_nodes"]),
            }
        if name == "get_detection_evidence":
            return {
                "detection_reason_count": len(result["reason_to_event_ids"]),
                "alert_source_count": len(result["source_to_event_ids"]),
            }
        if isinstance(result, dict) and "incident_id" in result:
            return {
                "incident_id": result["incident_id"],
                "event_count": len(result.get("event_ids", [])),
                "severity": result.get("triage", {}).get("severity"),
            }
        return {"record_count": len(result) if hasattr(result, "__len__") else 1}

    @staticmethod
    def _evidence_refs(name: str, result: Any) -> list[str]:
        if name == "get_event" and isinstance(result, dict) and result.get("event_id") is not None:
            return [str(result["event_id"])]
        if isinstance(result, list):
            refs = set()
            for item in result:
                if not isinstance(item, dict):
                    continue
                if item.get("event_id") is not None:
                    refs.add(str(item["event_id"]))
                if item.get("from_event") is not None:
                    refs.add(str(item["from_event"]))
                if item.get("to_event") is not None:
                    refs.add(str(item["to_event"]))
            return sorted(refs)
        if name == "get_graph_neighborhood":
            return [item.removeprefix("event:") for item in result["member_event_nodes"]]
        if name == "get_detection_evidence":
            return sorted({
                event_id
                for event_ids in result["reason_to_event_ids"].values()
                for event_id in event_ids
            })
        if isinstance(result, dict):
            return list(result.get("event_ids", []))
        return []

def _write_report(incidents: list[dict[str, Any]], events: pd.DataFrame, graph: nx.DiGraph, path: Path) -> None:
    critical = sum(i["triage"]["severity"] == "CRITICAL" for i in incidents)
    high = sum(i["triage"]["severity"] == "HIGH" for i in incidents)
    medium = sum(i["triage"]["severity"] == "MEDIUM" for i in incidents)
    lines = [
        "# SOC Incident Investigation Report", "",
        "> Evidence-first graph investigation. Ground-truth dataset labels are not used to select alerts, construct the graph, correlate incidents, calculate severity or map ATT&CK hypotheses.",
        "> Severity is a heuristic triage priority, not a calibrated probability or confirmed compromise verdict.", "",
        "## 1. Executive summary", "",
        f"- Candidate incidents: **{len(incidents):,}**",
        f"- Events investigated: **{len(events):,}**",
        f"- Alert flows represented: **{int(events['flow_count'].sum()) if not events.empty else 0:,}**",
        f"- Graph size: **{graph.number_of_nodes():,} nodes / {graph.number_of_edges():,} edges**",
        f"- Priority distribution: **{critical} critical / {high} high / {medium} medium**", "",
        "## 2. Prioritised incident queue", "",
        "| Priority | Incident | Risk / 100 | Confidence | Events | Sources | Targets | Key evidence |",
        "|---|---|---:|---|---:|---:|---:|---|",
    ]
    for item in incidents:
        g = item["graph_analysis"]
        lines.append(
            f"| {item['triage']['severity']} | {item['incident_id']} — {item['title']} | "
            f"{item['triage']['risk_score']:.1f} | {item['triage']['confidence']} | "
            f"{len(item['event_ids'])} | {g['unique_sources']} | {g['unique_targets']} | "
            f"{', '.join(item['detection_reasons'][:2]) or 'Anomalous/correlated activity'} |"
        )
    lines.extend(["", "## 3. Analyst investigation findings", ""])
    if not incidents:
        lines.append("No alert events were supplied. This is not proof of benign traffic; verify ingestion, detector coverage and model health.")
    for item in incidents[:15]:
        g, triage = item["graph_analysis"], item["triage"]
        risk_breakdown = ", ".join(
            f"{name}={detail.get('contribution_points', 0.0):.1f}"
            for name, detail in triage.get("components", {}).items()
        ) or "not available"
        relation_breakdown = ", ".join(
            f"{name}={count}"
            for name, count in g.get("edge_relation_counts", {}).items()
        ) or "no correlated edges"
        lines.extend([
            f"### {item['incident_id']} — {item['title']}", "",
            f"**Severity:** {triage['severity']}  ",
            f"**Risk score:** {triage['risk_score']:.1f}/100  ",
            f"**Confidence:** {triage['confidence']}  ",
            f"**Window:** {item['start_time']} to {item['end_time']} ({item['duration_seconds']:.1f}s)", "",
            f"**Observed scope:** {len(item['event_ids'])} events, {item['total_flows']:,} flows, {g['unique_sources']} sources and {g['unique_targets']} destinations.",
            f"**Detection evidence:** {', '.join(item['detection_reasons']) or 'No behavioural rule token'}.",
            f"**Graph structure:** {g['graph_event_links']} event-to-event links, density {g.get('graph_density', 0.0):.4f}, {g['unique_services']} destination services, pivot hosts: {', '.join(g['pivot_hosts']) or 'none observed'}.",
            f"**Graph relationship types:** {relation_breakdown}.",
            f"**Risk score component contributions:** {risk_breakdown}.", "",
            "**Top central events:**",
        ])
        for central in g.get("top_central_events", [])[:5]:
            lines.append(
                f"- {central['event_id']}: degree centrality {central['degree_centrality']:.4f}, "
                f"betweenness centrality {central['betweenness_centrality']:.4f}"
            )
        lines.extend(["", "**Source-side leads:**",
        ])
        for lead in g["top_sources"][:3]:
            lines.append(f"- {lead['ip']} — {lead['unique_targets']} distinct destinations")
        lines.extend(["", "**Destination-side leads:**"])
        for lead in g["top_targets"][:3]:
            lines.append(f"- {lead['ip']} — {lead['unique_sources']} distinct sources")
        lines.extend(["", "**Chronological event chain:**"])
        for event in item["timeline"][:12]:
            ports = ", ".join(str(p) for p in event["ports"]) if event["ports"] else "not recorded"
            lines.append(
                f"- {event['event_id']} {event['timestamp']}: {event['source']} -> {event['destination']} "
                f"({event['protocol']}, ports {ports}, {event['flows']} flows; {event['evidence']})"
            )
        if len(item["timeline"]) > 12:
            lines.append(f"- {len(item['timeline']) - 12} additional events are retained in JSON/CSV.")
        lines.extend(["", "**MITRE ATT&CK hypotheses (not confirmed):**"])
        if item["attack_hypotheses"]:
            for h in item["attack_hypotheses"]:
                lines.append(
                    f"- **{h['technique_id']} — {h['technique']}** ({h['confidence']} confidence): "
                    f"{h['evidence']} Caveat: {h['caveat']}"
                )
        else:
            lines.append("- No technique assigned: available network evidence is insufficient.")
        lines.extend(["", "**Recommended SOC actions:**"])
        lines.extend(f"- {action}" for action in item["recommended_actions"])
        investigation = item.get("investigation_agent", {})
        lines.extend([
            "",
            "**Tool-assisted agent investigation:**",
            f"- Mode: {investigation.get('mode', 'not run')}",
            f"- Tools executed: {len(investigation.get('tool_calls', []))}",
            f"- Evidence-linked findings: {len(investigation.get('findings', []))}",
        ])
        if investigation.get("narrative"):
            lines.append(f"- Analyst synthesis: {investigation['narrative']}")
        for finding in investigation.get("findings", [])[:8]:
            refs = ", ".join(finding.get("evidence_event_ids", []))
            lines.append(f"- {finding['claim']} Evidence: {refs or 'not linked'}")
        lines.append(
            f"- Model findings accepted/rejected: "
            f"{investigation.get('model_findings_accepted', 0)}/"
            f"{investigation.get('model_findings_rejected', 0)}"
        )
        lines.extend(["", f"**Evidence event IDs:** {', '.join(item['event_ids'])}", "", "---", ""])

    lines.extend([
        "## 4. Graph-analysis method", "",
        "The graph contains typed host, event, service and detection nodes. Events are linked independently by shared source, shared destination, shared destination service and target-to-source host pivots. Connected event components form candidate incidents. The analysis measures source fan-out, destination convergence, service diversity and temporal chains.", "",
        "Isolation Forest contributes one supporting signal. Behavioural detections can independently raise alerts, while graph relationships provide investigation context. The risk score combines rule diversity, persistence, graph fan-out/convergence, service diversity and (when present) relative anomaly score. It is a prioritisation heuristic, not a probability.", "",
        "## 5. Data limitations and analyst validation", "",
        "- CICIDS2017 is a labelled benchmark dataset, not live SOC telemetry. Ground-truth Label is excluded from alert selection and all investigation stages; use it separately for offline evaluation only.",
        "- Behaviour rules use fixed time buckets and can miss activity spanning bucket boundaries. Streaming deployment requires stateful rolling windows.",
        "- A flow graph cannot prove successful compromise, credential validity, process execution or business impact.",
        "- ATT&CK mappings are hypotheses grounded in network observations, not definitive attribution.",
        "- Validate high-priority findings against firewall, IDS, DNS, proxy, identity, EDR and packet-capture telemetry before containment.", "",
        "## 6. Generated artefacts", "",
        "- attack_events.csv: detector-derived event records.",
        "- attack_graph.gexf: typed graph for Gephi or compatible graph tooling.",
        "- incident_investigation.csv: event-to-incident assignment and triage.",
        "- incident_investigation.json: structured incident dossiers, graph findings, ATT&CK hypotheses and response actions.", "",
    ])
    path.write_text("\n".join(lines), encoding="utf-8")


def run_soc_investigation(
    alert_flows: pd.DataFrame,
    output_dir: str | Path,
    *,
    reasoner=None,
    pipeline_context: dict[str, Any] | None = None,
) -> tuple[pd.DataFrame, nx.DiGraph, dict[str, Any]]:
    """Run correlation -> incident formation -> graph -> risk -> agent tools -> report."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    events = build_soc_events(alert_flows)
    return run_soc_investigation_from_events(
        events,
        out,
        reasoner=reasoner,
        alert_flow_count=len(alert_flows),
        pipeline_context=pipeline_context,
    )


def run_soc_investigation_from_events(
    events: pd.DataFrame,
    output_dir: str | Path,
    *,
    reasoner=None,
    alert_flow_count: int | None = None,
    pipeline_context: dict[str, Any] | None = None,
) -> tuple[pd.DataFrame, nx.DiGraph, dict[str, Any]]:
    """Continue the canonical workflow from an already-formed event table."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    events = events.copy()
    required = {
        "event_id", "start_time", "end_time", "src_ip", "dst_ip",
        "protocol", "flow_count",
    }
    missing = required - set(events.columns)
    if missing:
        raise ValueError(f"Event contract is missing columns: {sorted(missing)}")
    if "detection_reasons" not in events.columns:
        events["detection_reasons"] = "LEGACY_EVENT_IMPORT"
    if "alert_sources" not in events.columns:
        events["alert_sources"] = "LEGACY_EVENT_IMPORT"
    if "attack_type" not in events.columns:
        events["attack_type"] = events["detection_reasons"]
    if "mean_anomaly_score" not in events.columns:
        events["mean_anomaly_score"] = pd.NA
    if "dst_ports" not in events.columns:
        events["dst_ports"] = [[] for _ in range(len(events))]
    for column in ("start_time", "end_time"):
        if not events.empty:
            events[column] = pd.to_datetime(events[column], errors="coerce", utc=True, format="mixed")
    if not events.empty and events[["start_time", "end_time"]].isna().any().any():
        raise ValueError("Event contract contains invalid timestamps.")

    events.to_csv(out / "attack_events.csv", index=False)
    correlations = EventCorrelationAgent(events, max_gap_seconds=300).correlate()
    correlations.to_csv(out / "event_correlations.csv", index=False)
    graph = build_soc_graph(events, correlations)
    incidents = (
        SOCInvestigationOrchestrator(events, graph, correlations).run()
        if not events.empty else []
    )

    evidence_tools = IncidentEvidenceTools(incidents, events, graph)
    agent = AgenticInvestigationAgent(evidence_tools, reasoner=reasoner)
    for incident in incidents:
        investigation = agent.investigate(incident["incident_id"])
        incident["investigation_agent"] = investigation
        incident["recommended_actions"] = incident["recommended_actions"] + [
            action for action in investigation["recommended_actions"]
            if action not in incident["recommended_actions"]
        ]

    incident_map: dict[str, dict[str, Any]] = {}
    for incident in incidents:
        for eid in incident["event_ids"]:
            incident_map[eid] = {
                "incident_id": incident["incident_id"],
                "incident_title": incident["title"],
                "incident_risk_score": incident["triage"]["risk_score"],
                "incident_severity": incident["triage"]["severity"],
                "incident_confidence": incident["triage"]["confidence"],
            }
    evidence = events.copy()
    for column in ("incident_id", "incident_title", "incident_risk_score", "incident_severity", "incident_confidence"):
        evidence[column] = evidence["event_id"].astype(str).map(lambda eid: incident_map.get(eid, {}).get(column))
    if not evidence.empty:
        evidence = evidence.sort_values(["incident_risk_score", "start_time"], ascending=[False, True])
    evidence.to_csv(out / "incident_investigation.csv", index=False)

    # Persist the incident-level graph only after the incident nodes have been
    # attached to their member events.
    from .graph_builder import write_attack_graph_gexf
    write_attack_graph_gexf(graph, str(out / "attack_graph.gexf"))

    payload = {
        "workflow": "single_soc_incident_lifecycle",
        "ground_truth_labels_used": False,
        "risk_score_is_probability": False,
        "stage_sequence": [
            "alert_ingestion",
            "event_correlation",
            "incident_formation",
            "attack_graph_construction",
            "incident_risk_assessment",
            "agentic_tool_investigation",
            "evidence_backed_reporting",
        ],
        "event_count": len(events),
        "correlation_count": len(correlations),
        "incident_count": len(incidents),
        "incidents": incidents,
    }
    (out / "incident_investigation.json").write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    _write_report(incidents, events, graph, out / "incident_investigation_report.md")
    tool_call_count = sum(
        len(item.get("investigation_agent", {}).get("tool_calls", []))
        for item in incidents
    )
    manifest = {
        "pipeline": "cicids2017_soc_incident_investigation",
        "version": "1.0",
        "stages": [
            {"name": "data_ingestion", "status": "completed", "details": (pipeline_context or {}).get("ingestion", {})},
            {"name": "metadata_preprocessing", "status": "completed", "details": (pipeline_context or {}).get("preprocessing", {})},
            {"name": "ml_detection", "status": "completed", "details": (pipeline_context or {}).get("ml_detection", {})},
            {"name": "behavioural_detection", "status": "completed", "details": (pipeline_context or {}).get("behavioural_detection", {})},
            {"name": "alert_fusion", "status": "completed", "output": "suspicious_flows_with_metadata.csv"},
            {"name": "event_aggregation", "status": "completed", "output": "attack_events.csv"},
            {"name": "event_correlation", "status": "completed", "output": "event_correlations.csv"},
            {"name": "incident_formation", "status": "completed", "output": "incident_investigation.json"},
            {"name": "attack_graph_construction", "status": "completed", "output": "attack_graph.gexf"},
            {"name": "risk_assessment", "status": "completed", "output": "incident_investigation.json"},
            {"name": "agentic_investigation", "status": "completed", "tool_calls": tool_call_count},
            {"name": "evidence_backed_reporting", "status": "completed", "output": "incident_investigation_report.md"},
        ],
        "pipeline_context": pipeline_context or {},
        "counts": {
            "dataset_flows": (pipeline_context or {}).get("ingestion", {}).get("rows_loaded"),
            "alerts": alert_flow_count,
            "events": len(events),
            "correlations": len(correlations),
            "incidents": len(incidents),
            "graph_nodes": graph.number_of_nodes(),
            "graph_edges": graph.number_of_edges(),
            "agent_tool_calls": tool_call_count,
        },
        "artifacts": [
            "attack_events.csv",
            "event_correlations.csv",
            "attack_graph.gexf",
            "incident_investigation.csv",
            "incident_investigation.json",
            "incident_investigation_report.md",
        ],
        "ground_truth_labels_used_for_investigation": False,
    }
    (out / "soc_pipeline_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    summary = {
        "incident_count": len(incidents),
        "critical_incidents": sum(i["triage"]["severity"] == "CRITICAL" for i in incidents),
        "high_incidents": sum(i["triage"]["severity"] == "HIGH" for i in incidents),
        "graph_event_links": sum(i["graph_analysis"]["graph_event_links"] for i in incidents),
        "correlation_count": len(correlations),
        "agent_tool_calls": tool_call_count,
        "event_count": len(events),
        "graph_nodes": graph.number_of_nodes(),
        "graph_edges": graph.number_of_edges(),
        "report_path": str(out / "incident_investigation_report.md"),
        "json_path": str(out / "incident_investigation.json"),
        "csv_path": str(out / "incident_investigation.csv"),
        "manifest_path": str(out / "soc_pipeline_manifest.json"),
    }
    return events, graph, summary
