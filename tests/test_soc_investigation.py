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
