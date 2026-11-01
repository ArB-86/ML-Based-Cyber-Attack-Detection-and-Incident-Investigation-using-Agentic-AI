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


def build_soc_events(alert_flows: pd.DataFrame, event_gap_seconds: int = 60) -> pd.DataFrame:
    """Group alert flows by endpoint pair and time. Ground-truth labels are never read."""
    columns = [
        "event_id", "start_time", "end_time", "duration_seconds", "src_ip", "dst_ip",
        "protocol", "attack_type", "flow_count", "mean_anomaly_score", "min_anomaly_score",
        "src_ports", "dst_ports", "unique_src_ports", "unique_dst_ports",
        "detection_reasons", "alert_sources",
    ]
    if alert_flows.empty:
        return pd.DataFrame(columns=columns)

    work = normalize_columns(alert_flows).copy()
    work.columns = [str(column).strip().lower() for column in work.columns]
    required = {"timestamp", "src_ip", "dst_ip", "protocol", "alert"}
    missing = required - set(work.columns)
    if missing:
        raise ValueError(f"SOC event builder requires columns: {sorted(missing)}")
    work["timestamp"] = pd.to_datetime(work["timestamp"], errors="coerce", utc=True, format="mixed")
    if work["timestamp"].isna().any():
        raise ValueError("SOC event builder received invalid timestamps.")
    work = work.loc[_bool_series(work["alert"])].copy()
    if work.empty:
        return pd.DataFrame(columns=columns)
    work["src_ip"] = work["src_ip"].astype(str).str.strip()
    work["dst_ip"] = work["dst_ip"].astype(str).str.strip()
    work = work.sort_values("timestamp", kind="stable")

    groups: list[pd.DataFrame] = []
    for _, group in work.groupby(["src_ip", "dst_ip", "protocol"], dropna=False, sort=True):
        group = group.sort_values("timestamp", kind="stable")
        indices: list[Any] = []
        previous = None
        for index, row in group.iterrows():
            timestamp = row["timestamp"]
            gap = None if previous is None else (timestamp - previous).total_seconds()
            if indices and gap > event_gap_seconds:
                groups.append(group.loc[indices].copy())
                indices = []
            indices.append(index)
            previous = timestamp
        if indices:
            groups.append(group.loc[indices].copy())

    groups.sort(key=lambda rows: (rows["timestamp"].min(), str(rows["src_ip"].iloc[0]), str(rows["dst_ip"].iloc[0])))
    records: list[dict[str, Any]] = []
    for number, rows in enumerate(groups, start=1):
        reasons = _tokens(rows.get("detection_reasons", pd.Series(dtype=object))) or {"UNSPECIFIED_DETECTION"}
        sources = _tokens(rows.get("alert_sources", pd.Series(dtype=object)))
        scores = pd.to_numeric(rows.get("anomaly_score", pd.Series(index=rows.index, dtype=float)), errors="coerce")
        src_port_values = pd.to_numeric(rows.get("src_port", pd.Series(index=rows.index, dtype=float)), errors="coerce").dropna()
        dst_port_values = pd.to_numeric(rows.get("dst_port", pd.Series(index=rows.index, dtype=float)), errors="coerce").dropna()
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


def build_soc_graph(events: pd.DataFrame, max_gap_seconds: int = 300) -> nx.DiGraph:
    """Typed host-event-service-detection graph with temporal links and pivots."""
    graph = nx.DiGraph()
    graph.graph["schema"] = "soc-investigation-graph-v2"
    graph.graph["ground_truth_labels_used"] = False
    if events.empty:
        return graph

    work = events.copy()
    for column in ("start_time", "end_time"):
        work[column] = pd.to_datetime(work[column], errors="coerce", utc=True, format="mixed")
    if work[["start_time", "end_time"]].isna().any().any():
        raise ValueError("Graph construction requires valid event timestamps.")

    entity_groups: dict[tuple[str, str], list[pd.Series]] = {}
    received: dict[str, list[tuple[pd.Timestamp, str]]] = {}
    initiated: dict[str, list[tuple[pd.Timestamp, str]]] = {}
    for _, event in work.iterrows():
        eid, src, dst = str(event["event_id"]), str(event["src_ip"]), str(event["dst_ip"])
        enode, snode, dnode = f"event:{eid}", f"host:{src}", f"host:{dst}"
        graph.add_node(snode, node_type="host", label=src, ip=src)
        graph.add_node(dnode, node_type="host", label=dst, ip=dst)
        event_attrs = {
            "node_type": "event", "event_id": eid, "label": eid,
            "start_time": event["start_time"].isoformat(),
            "end_time": event["end_time"].isoformat(),
            "protocol": str(event["protocol"]), "flow_count": int(event["flow_count"]),
            "detection_reasons": str(event.get("detection_reasons", "")),
        }
        score = event.get("mean_anomaly_score")
        if score is not None and pd.notna(score):
            event_attrs["mean_anomaly_score"] = float(score)
        graph.add_node(enode, **event_attrs)
        _add_edge(graph, snode, enode, "originates")
        _add_edge(graph, enode, dnode, "targets")
        entity_groups.setdefault(("source", src), []).append(event)
        entity_groups.setdefault(("target", dst), []).append(event)
        received.setdefault(dst, []).append((event["end_time"], eid))
        initiated.setdefault(src, []).append((event["start_time"], eid))

        ports = event.get("dst_ports", [])
        if not isinstance(ports, (list, tuple, set)):
            ports = []
        for port in sorted({int(p) for p in ports if str(p).isdigit() and 0 <= int(p) <= 65535}):
            service = f"service:{str(event['protocol']).lower()}/{port}"
            graph.add_node(service, node_type="service", label=f"{event['protocol']}/{port}", port=port)
            _add_edge(graph, enode, service, "touches_service")
            entity_groups.setdefault(("service", f"{str(event['protocol']).lower()}/{port}"), []).append(event)

        for reason in str(event.get("detection_reasons", "")).split(";"):
            reason = reason.strip()
            if reason:
                detection = f"detection:{reason}"
                graph.add_node(detection, node_type="detection", label=reason)
                _add_edge(graph, enode, detection, "triggered_by")

    # Correlate adjacent events independently for each shared entity. Same source
    # OR same destination OR same service is enough; no AND condition.
    for (kind, entity), rows in entity_groups.items():
        rows.sort(key=lambda row: (row["start_time"], row["end_time"]))
        for previous, current in zip(rows, rows[1:]):
            if str(previous["event_id"]) == str(current["event_id"]):
                continue
            gap = (current["start_time"] - previous["end_time"]).total_seconds()
            if 0 <= gap <= max_gap_seconds:
                _add_edge(graph, f"event:{previous['event_id']}", f"event:{current['event_id']}",
                          f"same_{kind}_temporal", gap_seconds=float(gap), shared_entity=entity)

    # Host pivot: a target later becomes a source. Connect the nearest preceding
    # inbound event rather than all historical pairs.
    for host, source_events in initiated.items():
        prior = sorted(received.get(host, []), key=lambda item: item[0])
        prior_times = [item[0] for item in prior]
        for start_time, source_eid in source_events:
            pos = bisect_right(prior_times, start_time) - 1
            if pos < 0:
                continue
            end_time, target_eid = prior[pos]
            gap = (start_time - end_time).total_seconds()
            if target_eid != source_eid and 0 <= gap <= max_gap_seconds:
                _add_edge(graph, f"event:{target_eid}", f"event:{source_eid}",
                          "host_pivot", gap_seconds=float(gap), pivot_host=host)
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
        return {
            "event_count": int(len(rows)),
            "graph_event_links": int(self.event_graph.subgraph(component).number_of_edges()),
            "unique_sources": int(rows["src_ip"].nunique()),
            "unique_targets": int(rows["dst_ip"].nunique()),
            "unique_services": len(dst_ports),
            "destination_ports": dst_ports,
            "max_source_fanout": int(max(src_fanout.values(), default=0)),
            "max_target_fanin": int(max(dst_fanin.values(), default=0)),
            "top_sources": [{"ip": str(ip), "unique_targets": int(n)}
                            for ip, n in sorted(src_fanout.items(), key=lambda x: (-x[1], str(x[0])))[:5]],
            "top_targets": [{"ip": str(ip), "unique_sources": int(n)}
                            for ip, n in sorted(dst_fanin.items(), key=lambda x: (-x[1], str(x[0])))[:5]],
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
        if reasons.intersection({"PORT_SCAN", "HORIZONTAL_SCAN", "HIGH_SOURCE_FANOUT"}):
            hypotheses.append({
                "technique_id": "T1046", "technique": "Network Service Discovery",
                "confidence": "medium",
                "evidence": "A source probed multiple destination services or hosts in a bounded time window.",
                "caveat": "Check authorised scanner schedules, firewall and IDS telemetry.",
            })
        if "DISTRIBUTED_DOS_PATTERN" in reasons or graph_data["max_target_fanin"] >= 15:
            hypotheses.append({
                "technique_id": "T1498", "technique": "Network Denial of Service",
                "confidence": "medium",
                "evidence": "A destination received flows from many distinct sources in a bounded interval.",
                "caveat": "Flow metadata alone does not establish service impact or malicious intent.",
            })
        if "BRUTE_FORCE_PATTERN" in reasons:
            hypotheses.append({
                "technique_id": "T1110", "technique": "Brute Force",
                "confidence": "medium",
                "evidence": "Repeated flows targeted an authentication service from one source to one destination.",
                "caveat": "Authentication success/failure logs are required to confirm credential guessing.",
            })
        if graph_data["pivot_hosts"] and {22, 445, 3389, 5985, 5986, 5900}.intersection(graph_data["destination_ports"]):
            hypotheses.append({
                "technique_id": "T1021", "technique": "Remote Services",
                "confidence": "low",
                "evidence": "A host was targeted and later initiated another related flow involving a remote-access port.",
                "caveat": "A pivot is an investigation lead, not proof of lateral movement.",
            })
        return hypotheses


class IncidentTriageAgent:
    """Rank incidents with transparent evidence components, not attack-type weights."""
    @staticmethod
    def score(rows: pd.DataFrame, graph_data: dict[str, Any],
              hypotheses: list[dict[str, str]], anomaly_strength: float | None) -> dict[str, Any]:
        reasons = _tokens(rows.get("detection_reasons", pd.Series(dtype=object)))
        behavioural = reasons - {"ISOLATION_FOREST_ANOMALY", "ANOMALY"}
        parts = [
            (30.0, min(1.0, len(behavioural) / 3.0)),
            (20.0, min(1.0, math.log1p(len(rows)) / math.log1p(10))),
            (20.0, min(1.0, graph_data["max_source_fanout"] / 20.0)),
            (15.0, min(1.0, graph_data["max_target_fanin"] / 20.0)),
            (10.0, min(1.0, graph_data["unique_services"] / 20.0)),
        ]
        if anomaly_strength is not None:
            parts.append((5.0, max(0.0, min(1.0, anomaly_strength))))
        risk = round(100.0 * sum(weight * score for weight, score in parts) / sum(weight for weight, _ in parts), 1)
        severity = "CRITICAL" if risk >= 80 else "HIGH" if risk >= 60 else "MEDIUM" if risk >= 35 else "LOW"
        signals = int(bool(behavioural))
        signals += int(graph_data["graph_event_links"] > 0 or bool(graph_data["pivot_hosts"]))
        signals += int(anomaly_strength is not None)
        signals += int(len(hypotheses) > 1)
        confidence = "HIGH" if signals >= 3 and len(rows) >= 4 else "MEDIUM" if signals >= 2 or len(rows) >= 3 else "LOW"
        return {
            "risk_score": risk, "severity": severity, "confidence": confidence,
            "independent_signal_count": signals,
            "scoring_note": "Heuristic triage priority, not a calibrated probability of compromise.",
        }


class SOCInvestigationOrchestrator:
    """Coordinate graph analyst, threat hunter and incident triage stages."""
    def __init__(self, events: pd.DataFrame, graph: nx.DiGraph):
        self.events = events.copy().reset_index(drop=True)
        self.graph = graph
        self.graph_agent = GraphAnalystAgent(graph)
        scores = pd.to_numeric(self.events.get("mean_anomaly_score", pd.Series(index=self.events.index, dtype=float)), errors="coerce")
        if scores.notna().any():
            strength = 1.0 - scores.rank(method="average", pct=True)
            self.anomaly_strength = dict(zip(self.events["event_id"].astype(str), strength.fillna(0.0)))
        else:
            self.anomaly_strength = {}

    def run(self) -> list[dict[str, Any]]:
        components = []
        for component in nx.connected_components(self.graph_agent.event_graph):
            ids = [node.removeprefix("event:") for node in component]
            rows = self.events[self.events["event_id"].astype(str).isin(ids)]
            if not rows.empty:
                components.append((rows["start_time"].min(), component, rows))
        components.sort(key=lambda item: item[0])
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
        lines.extend([
            f"### {item['incident_id']} — {item['title']}", "",
            f"**Severity:** {triage['severity']}  ",
            f"**Risk score:** {triage['risk_score']:.1f}/100  ",
            f"**Confidence:** {triage['confidence']}  ",
            f"**Window:** {item['start_time']} to {item['end_time']} ({item['duration_seconds']:.1f}s)", "",
            f"**Observed scope:** {len(item['event_ids'])} events, {item['total_flows']:,} flows, {g['unique_sources']} sources and {g['unique_targets']} destinations.",
            f"**Detection evidence:** {', '.join(item['detection_reasons']) or 'No behavioural rule token'}.",
            f"**Graph structure:** {g['graph_event_links']} event-to-event links, {g['unique_services']} destination services, pivot hosts: {', '.join(g['pivot_hosts']) or 'none observed'}.", "",
            "**Source-side leads:**",
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


def run_soc_investigation(alert_flows: pd.DataFrame, output_dir: str | Path) -> tuple[pd.DataFrame, nx.DiGraph, dict[str, Any]]:
    """Build the SOC graph, run analyst stages and write structured report artefacts."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    events = build_soc_events(alert_flows)
    for column in ("start_time", "end_time"):
        if not events.empty:
            events[column] = pd.to_datetime(events[column], errors="coerce", utc=True, format="mixed")
    events.to_csv(out / "attack_events.csv", index=False)
    graph = build_soc_graph(events)
    incidents = SOCInvestigationOrchestrator(events, graph).run() if not events.empty else []

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

    payload = {
        "workflow": "soc_graph_investigation_orchestrator",
        "ground_truth_labels_used": False,
        "risk_score_is_probability": False,
        "event_count": len(events),
        "incident_count": len(incidents),
        "incidents": incidents,
    }
    (out / "incident_investigation.json").write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    _write_report(incidents, events, graph, out / "incident_investigation_report.md")
    summary = {
        "incident_count": len(incidents),
        "critical_incidents": sum(i["triage"]["severity"] == "CRITICAL" for i in incidents),
        "high_incidents": sum(i["triage"]["severity"] == "HIGH" for i in incidents),
        "graph_event_links": sum(i["graph_analysis"]["graph_event_links"] for i in incidents),
        "event_count": len(events),
        "graph_nodes": graph.number_of_nodes(),
        "graph_edges": graph.number_of_edges(),
        "report_path": str(out / "incident_investigation_report.md"),
        "json_path": str(out / "incident_investigation.json"),
        "csv_path": str(out / "incident_investigation.csv"),
    }
    return events, graph, summary
