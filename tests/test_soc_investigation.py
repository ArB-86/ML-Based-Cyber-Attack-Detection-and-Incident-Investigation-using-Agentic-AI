import json

import pandas as pd

from attack_graph.soc_detection import BehaviourThresholds, detect_behavioral_alerts, merge_detector_outputs
from attack_graph.soc_investigation import build_soc_events, build_soc_graph, run_soc_investigation


def _time(minute: int, second: int = 0) -> str:
    return f"2026-01-01 10:{minute:02d}:{second:02d}"


def test_behavioural_rules_are_independent_of_ground_truth_label():
    rows = [
        {
            "Timestamp": _time(0, second),
            "Source IP": "10.0.0.1",
            "Destination IP": "10.0.0.9",
            "Source Port": 40000 + port,
            "Destination Port": port,
            "Label": "BENIGN",
        }
        for second, port in enumerate(range(2000, 2012))
    ]
    benign = pd.DataFrame(rows)
    attack = benign.assign(Label="PortScan")
    thresholds = BehaviourThresholds(port_scan_unique_ports=10)
    first = detect_behavioral_alerts(benign, thresholds)
    second = detect_behavioral_alerts(attack, thresholds)
    assert first["rule_alert"].tolist() == second["rule_alert"].tolist()
    assert first["detection_reasons"].tolist() == second["detection_reasons"].tolist()
    assert first["rule_alert"].all()
    assert first["detection_reasons"].str.contains("PORT_SCAN").all()


def test_rule_alerts_reach_soc_investigation_even_when_label_says_benign(tmp_path):
    rows = pd.DataFrame([
        {
            "timestamp": _time(0, second),
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.9",
            "src_port": 40000 + port,
            "dst_port": port,
            "protocol": 6,
            "anomaly_score": 0.5,
            "label": "BENIGN",
        }
        for second, port in enumerate(range(2000, 2012))
    ])
    scored = merge_detector_outputs(rows, anomaly_threshold=0.1)
    assert scored["rule_alert"].all()
    assert not scored["model_alert"].any()
    assert scored["alert"].all()

    events, graph, summary = run_soc_investigation(scored, tmp_path)
    assert len(events) == 1
    assert int(events.iloc[0]["flow_count"]) == 12
    assert "PORT_SCAN" in events.iloc[0]["detection_reasons"]
    assert summary["incident_count"] == 1
    report = (tmp_path / "incident_investigation_report.md").read_text()
    assert "Network Service Discovery" in report
    payload = json.loads((tmp_path / "incident_investigation.json").read_text())
    assert payload["ground_truth_labels_used"] is False


def test_graph_links_shared_target_and_host_pivot_for_soc_chain(tmp_path):
    flows = pd.DataFrame([
        {
            "timestamp": _time(0), "src_ip": "A", "dst_ip": "B", "protocol": 6,
            "src_port": 50000, "dst_port": 22, "alert": True,
            "detection_reasons": "BRUTE_FORCE_PATTERN", "alert_sources": "BEHAVIOURAL_RULE",
            "anomaly_score": 0.01,
        },
        {
            "timestamp": _time(1), "src_ip": "C", "dst_ip": "B", "protocol": 6,
            "src_port": 50001, "dst_port": 22, "alert": True,
            "detection_reasons": "BRUTE_FORCE_PATTERN", "alert_sources": "BEHAVIOURAL_RULE",
            "anomaly_score": 0.02,
        },
        {
            "timestamp": _time(2), "src_ip": "B", "dst_ip": "D", "protocol": 6,
            "src_port": 22, "dst_port": 445, "alert": True,
            "detection_reasons": "HIGH_SOURCE_FANOUT", "alert_sources": "BEHAVIOURAL_RULE",
            "anomaly_score": 0.03,
        },
    ])
    events = build_soc_events(flows)
    graph = build_soc_graph(events)
    relations = [
        attrs.get("relations", attrs.get("relation", ""))
        for _, _, attrs in graph.edges(data=True)
    ]
    assert any("same_target_temporal" in relation for relation in relations)
    assert any("host_pivot" in relation for relation in relations)

    summary = run_soc_investigation(flows, tmp_path)
    report = (tmp_path / "incident_investigation_report.md").read_text()
    payload = json.loads((tmp_path / "incident_investigation.json").read_text())
    assert summary[2]["incident_count"] == 1
    assert "T1110" in report
    assert "pivot hosts" in report
    assert payload["incidents"][0]["graph_analysis"]["pivot_hosts"] == ["B"]


def test_incident_graph_and_agent_tools_share_one_incident_id(tmp_path):
    flows = pd.DataFrame([
        {
            "timestamp": _time(0), "src_ip": "A", "dst_ip": "B", "protocol": 6,
            "src_port": 50000, "dst_port": 22, "alert": True,
            "detection_reasons": "BRUTE_FORCE_PATTERN", "alert_sources": "BEHAVIOURAL_RULE",
            "anomaly_score": 0.01,
        },
        {
            "timestamp": _time(1), "src_ip": "B", "dst_ip": "C", "protocol": 6,
            "src_port": 22, "dst_port": 445, "alert": True,
            "detection_reasons": "HIGH_SOURCE_FANOUT", "alert_sources": "BEHAVIOURAL_RULE",
            "anomaly_score": 0.02,
        },
    ])
    events, graph, summary = run_soc_investigation(flows, tmp_path)
    incident_nodes = [
        (node, attrs) for node, attrs in graph.nodes(data=True)
        if attrs.get("node_type") == "incident"
    ]
    assert len(incident_nodes) == 1

    incident_id = incident_nodes[0][1]["label"]
    assert graph.has_edge(f"incident:{incident_id}", "event:EVT-000001")
    assert graph.has_edge(f"incident:{incident_id}", "event:EVT-000002")

    payload = json.loads((tmp_path / "incident_investigation.json").read_text())
    dossier = payload["incidents"][0]
    assert dossier["incident_id"] == incident_id
    agent = dossier["investigation_agent"]
    assert agent["status"] == "completed"
    assert {call["tool"] for call in agent["tool_calls"]} == {
        "get_incident", "get_timeline", "get_graph_neighborhood", "get_detection_evidence"
    }
    assert agent["findings"]
    for finding in agent["findings"]:
        assert set(finding["evidence_event_ids"]).issubset(set(dossier["event_ids"]))

    manifest = json.loads((tmp_path / "soc_pipeline_manifest.json").read_text())
    assert manifest["counts"]["alerts"] == len(flows)
    assert manifest["counts"]["events"] == len(events)
    assert manifest["counts"]["incidents"] == 1
    assert manifest["counts"]["agent_tool_calls"] == 4
    assert (tmp_path / "event_correlations.csv").exists()
    assert (tmp_path / "attack_graph.gexf").exists()


def test_legacy_investigator_cli_reuses_canonical_workflow(tmp_path):
    from attack_graph.incident_investigator import run as run_legacy_investigator

    legacy_events = pd.DataFrame([{
        "event_id": "OLD-1",
        "start_time": _time(0),
        "end_time": _time(0, 5),
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "protocol": 6,
        "attack_type": "PortScan",
        "flow_count": 12,
        "mean_anomaly_score": 0.1,
        "ports_observed": "[(40000, 22), (40001, 80)]",
    }])
    source = tmp_path / "legacy_events.csv"
    output = tmp_path / "canonical_output"
    legacy_events.to_csv(source, index=False)

    run_legacy_investigator(str(source), str(output))
    payload = json.loads((output / "incident_investigation.json").read_text())
    assert payload["ground_truth_labels_used"] is False
    assert payload["incidents"][0]["detection_reasons"] == ["LEGACY_EVENT_IMPORT"]
    assert payload["incidents"][0]["investigation_agent"]["tool_calls"]


def test_llm_agent_selects_scoped_tools_and_rejects_unsupported_evidence(tmp_path):
    flows = pd.DataFrame([
        {
            "timestamp": _time(0), "src_ip": "A", "dst_ip": "B", "protocol": 6,
            "src_port": 50000, "dst_port": 22, "alert": True,
            "detection_reasons": "BRUTE_FORCE_PATTERN", "alert_sources": "BEHAVIOURAL_RULE",
            "anomaly_score": 0.01,
        },
        {
            "timestamp": _time(1), "src_ip": "B", "dst_ip": "C", "protocol": 6,
            "src_port": 22, "dst_port": 445, "alert": True,
            "detection_reasons": "HIGH_SOURCE_FANOUT", "alert_sources": "BEHAVIOURAL_RULE",
            "anomaly_score": 0.02,
        },
    ])
    calls = {"count": 0}

    def fake_reasoner(context):
        calls["count"] += 1
        if calls["count"] == 1:
            return {
                "tool_calls": [
                    {
                        "name": "get_host_activity",
                        "arguments": {"host_ip": "B"},
                    },
                    {
                        "name": "get_correlated_events",
                        "arguments": {
                            "event_id": "EVT-000001",
                            "relation_contains": "host_pivot",
                        },
                    },
                    {
                        "name": "get_event",
                        "arguments": {"event_id": "EVT-999999"},
                    },
                    {
                        "name": "get_host_activity",
                        "arguments": {"host_ip": "B", "incident_id": "INC-OTHER"},
                    },
                ],
                "preliminary_findings": [],
                "narrative": "Need to inspect pivot host B.",
            }
        return {
            "narrative": "Host B is a pivot lead; validate using endpoint telemetry.",
            "findings": [
                {
                    "claim": "Host B was targeted and later initiated another connection.",
                    "evidence_event_ids": ["EVT-000001", "EVT-000002"],
                    "confidence": "medium",
                },
                {
                    "claim": "An unrelated host executed malware.",
                    "evidence_event_ids": ["EVT-999999"],
                    "confidence": "high",
                },
            ],
        }

    _, _, summary = run_soc_investigation(flows, tmp_path, reasoner=fake_reasoner)
    payload = json.loads((tmp_path / "incident_investigation.json").read_text())
    agent = payload["incidents"][0]["investigation_agent"]

    assert calls["count"] == 2
    assert agent["mode"] == "tool_assisted_llm"
    assert agent["model_findings_accepted"] == 1
    assert agent["model_findings_rejected"] == 1
    assert any(
        call["tool"] == "get_host_activity" and call["status"] == "success"
        for call in agent["tool_calls"]
    )
    assert any(
        call["tool"] == "get_correlated_events" and call["status"] == "success"
        for call in agent["tool_calls"]
    )
    assert any(
        call["tool"] == "get_event" and call["status"] == "rejected"
        for call in agent["tool_calls"]
    )
    assert any(
        call["tool"] == "get_host_activity"
        and call["status"] == "rejected"
        and "Cross-incident" in call["error"]
        for call in agent["tool_calls"]
    )
    assert any(
        finding["source"] == "llm_evidence_validated"
        for finding in agent["findings"]
    )
    assert summary["agent_tool_calls"] >= 6


def test_reasoner_failure_falls_back_to_deterministic_investigation(tmp_path):
    flows = pd.DataFrame([
        {
            "timestamp": _time(0), "src_ip": "A", "dst_ip": "B", "protocol": 6,
            "src_port": 50000, "dst_port": 22, "alert": True,
            "detection_reasons": "BRUTE_FORCE_PATTERN", "alert_sources": "BEHAVIOURAL_RULE",
            "anomaly_score": 0.01,
        },
    ])

    def unavailable_reasoner(_context):
        raise TimeoutError("local reasoner unavailable")

    run_soc_investigation(flows, tmp_path, reasoner=unavailable_reasoner)
    payload = json.loads((tmp_path / "incident_investigation.json").read_text())
    agent = payload["incidents"][0]["investigation_agent"]
    assert agent["status"] == "completed"
    assert agent["mode"] == "tool_assisted_llm_fallback"
    assert "TimeoutError" in agent["reasoner_error"]
    assert agent["findings"]
    assert len(agent["tool_calls"]) >= 5
