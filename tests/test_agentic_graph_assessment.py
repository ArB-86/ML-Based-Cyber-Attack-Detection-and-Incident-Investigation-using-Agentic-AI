from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import networkx as nx
import pandas as pd

from attack_graph.agentic_investigator import (
    AttackGraphInvestigationTools,
    _offline_result,
    _write_markdown,
)


def make_case(rows: list[dict]) -> tuple[pd.DataFrame, nx.DiGraph]:
    events = pd.DataFrame(rows)
    graph = nx.DiGraph()

    for row in rows:
        source = f"host:{row['src_ip']}"
        destination = f"host:{row['dst_ip']}"
        attack = f"attack:{row['attack_type']}"
        event = f"event:{row['event_id']}"
        graph.add_node(source, node_type="source", label=row["src_ip"])
        graph.add_node(destination, node_type="target", label=row["dst_ip"])
        graph.add_node(attack, node_type="attack_type", label=row["attack_type"])
        graph.add_node(
            event,
            node_type="event",
            label=row["event_id"],
            start_time=row["start_time"],
            end_time=row["end_time"],
        )
        graph.add_edge(source, event, relation="initiates")
        graph.add_edge(event, attack, relation="classified_as")
        graph.add_edge(event, destination, relation="targets")

    return events, graph


def event_row(event_id: str, source: str, destination: str, minute: int) -> dict:
    stamp = f"2017-05-07T10:{minute:02d}:00+00:00"
    return {
        "event_id": event_id,
        "src_ip": source,
        "dst_ip": destination,
        "attack_type": "DoS Hulk",
        "protocol": 6,
        "flow_count": 100,
        "mean_anomaly_score": -0.05,
        "start_time": stamp,
        "end_time": stamp,
    }


class GraphSOCAssessmentTests(unittest.TestCase):
    def test_exact_source_destination_label_cohort_and_temporal_edges(self):
        rows = [
            event_row("EVT-00001", "10.0.0.1", "10.0.0.2", 10),
            event_row("EVT-00002", "10.0.0.1", "10.0.0.2", 11),
            event_row("EVT-00003", "10.0.0.1", "10.0.0.2", 12),
        ]
        events, graph = make_case(rows)
        graph.add_edge("event:EVT-00001", "event:EVT-00002", relation="precedes", gap_seconds=60.0)
        graph.add_edge("event:EVT-00002", "event:EVT-00003", relation="precedes", gap_seconds=60.0)

        tools = AttackGraphInvestigationTools(events, graph, rows[1])
        assessment = tools.build_soc_assessment()

        self.assertEqual(assessment["source_host_profile"]["event_count"], 3)
        self.assertEqual(assessment["destination_host_profile"]["event_count"], 3)
        self.assertEqual(assessment["attack_type_cluster_profile"]["event_count"], 3)
        self.assertEqual(assessment["exact_source_destination_label_cluster"]["event_count"], 3)
        self.assertEqual(len(assessment["direct_temporal_predecessors"]), 1)
        self.assertEqual(len(assessment["direct_temporal_successors"]), 1)
        self.assertEqual(len(assessment["temporal_sequence"]), 3)
        self.assertIn("3 event nodes share", assessment["executive_assessment"])

        investigation = _offline_result(
            rows[1],
            {"graph_analysis": {"soc_assessment": assessment}},
        )
        payload = {
            "event_id": "EVT-00002",
            "mode": "offline_graph_evidence",
            "target_event": rows[1],
            "graph_analysis": {"soc_assessment": assessment, "graph_metrics": {}},
            "investigation": investigation,
            "evidence": {"related_event_count": 2},
        }
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "report.md"
            _write_markdown(payload, report_path)
            report = report_path.read_text(encoding="utf-8")

        self.assertIn("Executive SOC assessment", report)
        self.assertIn("Source-host investigation", report)
        self.assertIn("Attack-type cluster and exact-tuple test", report)
        self.assertIn("Temporal investigation", report)
        self.assertIn("Secondary detector context", report)
        self.assertIn("Recommended analyst actions", report)

    def test_multi_source_label_cluster_is_not_reported_as_single_tuple(self):
        rows = [
            event_row("EVT-00001", "10.0.0.1", "10.0.0.9", 10),
            event_row("EVT-00002", "10.0.0.2", "10.0.0.9", 11),
        ]
        events, graph = make_case(rows)
        tools = AttackGraphInvestigationTools(events, graph, rows[0])
        assessment = tools.build_soc_assessment()

        self.assertEqual(assessment["attack_type_cluster_profile"]["event_count"], 2)
        self.assertEqual(assessment["attack_type_cluster_profile"]["distinct_source_count"], 2)
        self.assertEqual(assessment["exact_source_destination_label_cluster"]["event_count"], 1)
        self.assertIn("multi-source graph pattern", assessment["executive_assessment"].lower())


if __name__ == "__main__":
    unittest.main()
