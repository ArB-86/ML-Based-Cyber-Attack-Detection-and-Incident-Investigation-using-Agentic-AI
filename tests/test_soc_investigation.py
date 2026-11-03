import json

import pandas as pd

from attack_graph.event_builder import EventConfig, build_attack_events
from attack_graph.soc_detection import BehaviourThresholds, detect_behavioral_alerts, merge_detector_outputs
from attack_graph.pipeline import PipelineConfig, run_pipeline
from attack_graph.soc_investigation import (
    EventCorrelationAgent,
    IncidentFormationAgent,
    build_soc_events,
    build_soc_graph,
    run_soc_investigation,
)


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
    # Port-scan patterns are retained for analyst review, not promoted
    # directly into the primary alert stream.
    assert not first["rule_alert"].any()
    assert first["review_alert"].all()
    assert first["review_reasons"].str.contains("PORT_SCAN").all()
    assert first["matched_rule_reasons"].str.contains("PORT_SCAN").all()


def test_rule_alerts_reach_soc_investigation_even_when_label_says_benign(tmp_path):
    rows = pd.DataFrame([
        {
            "timestamp": _time(0, second),
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.9",
            "src_port": 40000 + port,
            "dst_port": 22,
            "protocol": 6,
            "anomaly_score": 0.5,
            "label": "BENIGN",
        }
        for second, port in enumerate(range(2000, 2012))
    ])
    scored = merge_detector_outputs(rows, anomaly_threshold=0.1)
    assert scored["rule_alert"].all()
    assert not scored["review_alert"].any()
    assert not scored["model_alert"].any()
    assert scored["alert"].all()
    assert scored["detection_reasons"].str.contains("BRUTE_FORCE_PATTERN").all()

    events, graph, summary = run_soc_investigation(scored, tmp_path)
    assert len(events) == 1
    assert int(events.iloc[0]["flow_count"]) == 12
    assert "BRUTE_FORCE_PATTERN" in events.iloc[0]["detection_reasons"]
    assert summary["incident_count"] == 1
    report = (tmp_path / "incident_investigation_report.md").read_text()
    assert "Brute Force" in report
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
    assert summary[2]["incident_count"] == 2
    assert "T1110" in report
    assert "pivot hosts" in report
    pivot_incidents = [
        item for item in payload["incidents"]
        if item["graph_analysis"]["pivot_hosts"] == ["B"]
    ]
    assert len(pivot_incidents) == 1
    assert pivot_incidents[0]["attack_hypotheses"]


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
                        "arguments": {"event_id": "EVT-000001"},
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
                    "claim_type": "host_pivot_lead",
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
        call["tool"] == "get_event" and call["status"] == "success"
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
        finding["source"] == "llm_semantic_validated"
        for finding in agent["findings"]
    )
    assert summary["agent_tool_calls"] >= 6


def test_cli_loads_existing_reasoner_callback_without_runtime_configuration(tmp_path, monkeypatch):
    import sys
    import types

    from attack_graph.pipeline import load_reasoner_callable

    plugin = types.ModuleType("existing_local_reasoner_plugin")

    def configured_reasoner(context):
        return {"narrative": "existing callback", "tool_calls": []}

    plugin.existing_reasoner = configured_reasoner
    monkeypatch.setitem(sys.modules, plugin.__name__, plugin)

    loaded = load_reasoner_callable(
        "existing_local_reasoner_plugin:existing_reasoner"
    )

    assert loaded is configured_reasoner
    assert loaded({"task": "smoke test"})["narrative"] == "existing callback"


def test_reasoner_callable_loader_rejects_invalid_targets(monkeypatch):
    import sys
    import types
    import pytest

    from attack_graph.pipeline import load_reasoner_callable

    plugin = types.ModuleType("reasoner_without_callable")
    plugin.value = "not callable"
    monkeypatch.setitem(sys.modules, plugin.__name__, plugin)

    with pytest.raises(ValueError, match="module:callable"):
        load_reasoner_callable("invalid-format")

    with pytest.raises(TypeError, match="not callable"):
        load_reasoner_callable("reasoner_without_callable:value")


def test_agent_investigation_limit_runs_one_llm_incident_and_marks_rest_skipped(tmp_path):
    flows = pd.DataFrame([
        {
            "timestamp": _time(0), "src_ip": "A", "dst_ip": "B", "protocol": 6,
            "src_port": 50000, "dst_port": 443, "alert": True,
            "detection_reasons": "ISOLATION_FOREST_ANOMALY",
            "alert_sources": "ISOLATION_FOREST", "anomaly_score": 0.01,
        },
        {
            "timestamp": _time(1), "src_ip": "A", "dst_ip": "C", "protocol": 6,
            "src_port": 50001, "dst_port": 443, "alert": True,
            "detection_reasons": "ISOLATION_FOREST_ANOMALY",
            "alert_sources": "ISOLATION_FOREST", "anomaly_score": 0.02,
        },
        {
            "timestamp": _time(10), "src_ip": "X", "dst_ip": "Y", "protocol": 6,
            "src_port": 51000, "dst_port": 443, "alert": True,
            "detection_reasons": "ISOLATION_FOREST_ANOMALY",
            "alert_sources": "ISOLATION_FOREST", "anomaly_score": 0.03,
        },
        {
            "timestamp": _time(11), "src_ip": "X", "dst_ip": "Z", "protocol": 6,
            "src_port": 51001, "dst_port": 443, "alert": True,
            "detection_reasons": "ISOLATION_FOREST_ANOMALY",
            "alert_sources": "ISOLATION_FOREST", "anomaly_score": 0.04,
        },
    ])

    reasoner_calls = []

    def fake_reasoner(context):
        reasoner_calls.append(context)
        return {
            "tool_calls": [],
            "findings": [],
            "narrative": "Single-incident smoke-test response.",
        }

    _, _, summary = run_soc_investigation(
        flows,
        tmp_path,
        reasoner=fake_reasoner,
        max_agent_investigations=1,
    )

    payload = json.loads(
        (tmp_path / "incident_investigation.json").read_text()
    )
    agents = [
        incident["investigation_agent"]
        for incident in payload["incidents"]
    ]

    assert summary["incident_count"] == 2
    assert summary["agent_investigations_executed"] == 1
    assert summary["agent_investigations_skipped"] == 1
    assert summary["reasoner_incidents"] == 1
    assert len(reasoner_calls) == 1
    assert sum(agent["mode"] == "tool_assisted_llm" for agent in agents) == 1
    assert sum(agent["mode"] == "not_run_limit" for agent in agents) == 1
    assert sum(agent["status"] == "skipped_by_limit" for agent in agents) == 1
    assert all(
        agent["reasoner_skipped_by_limit"]
        for agent in agents if agent["mode"] == "not_run_limit"
    )


def test_agent_investigation_limit_rejects_negative_values(tmp_path):
    flows = pd.DataFrame([
        {
            "timestamp": _time(0), "src_ip": "A", "dst_ip": "B", "protocol": 6,
            "src_port": 50000, "dst_port": 22, "alert": True,
            "detection_reasons": "BRUTE_FORCE_PATTERN",
            "alert_sources": "BEHAVIOURAL_RULE", "anomaly_score": 0.01,
        },
    ])

    import pytest

    with pytest.raises(ValueError, match="non-negative integer"):
        run_soc_investigation(
            flows,
            tmp_path,
            max_agent_investigations=-1,
        )


def test_llm_agent_supports_two_bounded_tool_rounds(tmp_path):
    flows = pd.DataFrame([
        {
            "timestamp": _time(0), "src_ip": "A", "dst_ip": "B", "protocol": 6,
            "src_port": 50000, "dst_port": 443, "alert": True,
            "detection_reasons": "ISOLATION_FOREST_ANOMALY",
            "alert_sources": "ISOLATION_FOREST",
            "anomaly_score": 0.01,
        },
        {
            "timestamp": _time(1), "src_ip": "A", "dst_ip": "C", "protocol": 6,
            "src_port": 50001, "dst_port": 443, "alert": True,
            "detection_reasons": "ISOLATION_FOREST_ANOMALY",
            "alert_sources": "ISOLATION_FOREST",
            "anomaly_score": 0.02,
        },
    ])

    calls = []

    def fake_reasoner(context):
        calls.append(context)
        call_number = len(calls)

        if call_number == 1:
            return {
                "tool_calls": [{
                    "name": "get_host_activity",
                    "arguments": {"host_ip": "A"},
                }],
                "preliminary_findings": [],
                "narrative": "Inspect source host A.",
            }

        if call_number == 2:
            assert context["completed_tool_results"][0]["tool"] == "get_host_activity"
            assert context["remaining_tool_call_budget"] == 7
            return {
                "tool_calls": [{
                    "name": "get_correlated_events",
                    "arguments": {
                        "event_id": "EVT-000001",
                        "relation_contains": "same_source_temporal",
                    },
                }],
                "preliminary_findings": [],
                "narrative": "Inspect the source-linked event pair.",
            }

        assert call_number == 3
        assert len(context["completed_tool_results"]) == 2
        return {
            "tool_calls": [],
            "narrative": "Source A generated two temporally correlated network-flow events.",
            "findings": [{
                "claim_type": "isolation_forest_anomaly",
                "claim": "These events carry Isolation Forest anomaly detection metadata.",
                "evidence_event_ids": ["EVT-000001", "EVT-000002"],
                "confidence": "high",
            }],
        }

    run_soc_investigation(flows, tmp_path, reasoner=fake_reasoner)

    payload = json.loads(
        (tmp_path / "incident_investigation.json").read_text()
    )
    agent = payload["incidents"][0]["investigation_agent"]

    assert len(calls) == 3
    assert agent["mode"] == "tool_assisted_llm"
    assert agent["llm_tool_rounds"] == 2
    assert agent["llm_tool_requests"] == 2
    assert agent["llm_tool_calls_executed"] == 2
    assert [item["phase"] for item in agent["reasoner_calls"]] == [
        "initial_plan",
        "tool_followup",
        "final_synthesis",
    ]
    assert sum(
        call["status"] == "success"
        and call["tool"] in {"get_host_activity", "get_correlated_events"}
        for call in agent["tool_calls"]
    ) == 2

    model_finding = next(
        finding for finding in agent["findings"]
        if finding["source"] == "llm_semantic_validated"
    )
    assert model_finding["claim_type"] == "isolation_forest_anomaly"
    assert model_finding["confidence"] == "low"
    assert model_finding["validation_scope"] == "detector_metadata_predicate"
    assert model_finding["claim_semantics_independently_verified"] is True
    assert model_finding["analyst_validation_required"] is True


def test_semantic_validator_requires_matching_detection_provenance():
    from attack_graph.soc_investigation import _validate_model_finding

    events = {
        "E1": {
            "event_id": "E1",
            "detection_reasons": "ISOLATION_FOREST_ANOMALY",
            "alert_sources": "ISOLATION_FOREST",
        },
        "E2": {
            "event_id": "E2",
            "detection_reasons": "ISOLATION_FOREST_ANOMALY",
            "alert_sources": "BEHAVIOURAL_RULE",
        },
    }
    finding = {
        "claim_type": "isolation_forest_anomaly",
        "claim": "Isolation Forest anomalies were observed.",
        "evidence_event_ids": ["E1", "E2"],
    }

    validated, error = _validate_model_finding(finding, events, {"E1", "E2"})

    assert error is None
    assert validated is not None
    assert validated["evidence_event_ids"] == ["E1"]
    assert validated["excluded_event_ids"] == ["E2"]
    assert validated["confidence"] == "low"
    assert validated["semantic_validation"]["status"] == "passed"


def test_semantic_validator_rejects_combined_or_unsupported_claims():
    from attack_graph.soc_investigation import _validate_model_finding

    events = {
        "E1": {
            "event_id": "E1",
            "context_signals": "HIGH_SOURCE_FANOUT;HORIZONTAL_SCAN",
        }
    }
    combined = {
        "claim": "High source fanout and horizontal scan suggest lateral movement.",
        "evidence_event_ids": ["E1"],
    }
    unsupported = {
        "claim": "The host was compromised and lateral movement succeeded.",
        "evidence_event_ids": ["E1"],
    }

    validated, error = _validate_model_finding(combined, events, {"E1"})
    assert validated is None
    assert "combines multiple evidence categories" in error

    validated, error = _validate_model_finding(unsupported, events, {"E1"})
    assert validated is None
    assert "cannot be inferred" in error


def test_semantic_validator_calculates_distinct_hosts_and_services():
    from attack_graph.soc_investigation import _validate_model_finding

    events = {
        "E1": {
            "event_id": "E1",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "6.0",
            "dst_ports": [443],
        },
        "E2": {
            "event_id": "E2",
            "src_ip": "10.0.0.3",
            "dst_ip": "10.0.0.4",
            "protocol": "17.0",
            "dst_ports": [53],
        },
    }
    finding = {
        "claim_type": "multi_host_multi_service",
        "claim": "The incident spans multiple hosts and services.",
        "evidence_event_ids": ["E1", "E2"],
    }

    validated, error = _validate_model_finding(finding, events, {"E1", "E2"})

    assert error is None
    assert validated is not None
    assert "4 distinct endpoint IPs" in validated["claim"]
    assert "2 distinct destination services" in validated["claim"]
    assert validated["validation_scope"] == "derived_event_metadata_metrics"


def test_semantic_validator_requires_exact_host_pivot_edge():
    from attack_graph.soc_investigation import _validate_model_finding

    events = {
        "E1": {"event_id": "E1"},
        "E2": {"event_id": "E2"},
        "E3": {"event_id": "E3"},
    }
    edges = [{
        "from": "event:E1",
        "to": "event:E2",
        "relation": "host_pivot",
        "pivot_host": "10.0.0.2",
    }]
    supported = {
        "claim_type": "host_pivot_lead",
        "claim": "A host pivot was observed.",
        "evidence_event_ids": ["E1", "E2"],
    }
    unsupported = {
        "claim_type": "host_pivot_lead",
        "claim": "A host pivot was observed.",
        "evidence_event_ids": ["E1", "E3"],
    }

    validated, error = _validate_model_finding(
        supported, events, {"E1", "E2", "E3"}, edges
    )
    assert error is None
    assert validated is not None
    assert validated["evidence_event_ids"] == ["E1", "E2"]
    assert "not proof" in validated["claim"]

    validated, error = _validate_model_finding(
        unsupported, events, {"E1", "E2", "E3"}, edges
    )
    assert validated is None
    assert "No exact host_pivot graph edge" in error


def test_semantic_validator_rejects_event_ids_outside_incident():
    from attack_graph.soc_investigation import _validate_model_finding

    events = {
        "E1": {
            "event_id": "E1",
            "detection_reasons": "BRUTE_FORCE_PATTERN",
        },
        "OUTSIDE": {
            "event_id": "OUTSIDE",
            "detection_reasons": "BRUTE_FORCE_PATTERN",
        },
    }
    finding = {
        "claim_type": "brute_force_flow_pattern",
        "claim": "A brute-force flow pattern was detected.",
        "evidence_event_ids": ["E1", "OUTSIDE"],
    }

    validated, error = _validate_model_finding(finding, events, {"E1"})
    assert validated is None
    assert "outside the current incident" in error


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


def test_legacy_event_builder_never_uses_dataset_label_for_alert_selection():
    raw = pd.DataFrame([
        {
            "Timestamp": _time(0, second),
            "Source IP": "10.0.0.1",
            "Destination IP": "10.0.0.9",
            "Source Port": 40000 + second,
            "Destination Port": 22,
            "Protocol": 6,
            "Label": "PortScan",
        }
        for second in range(3)
    ])
    try:
        build_attack_events(raw, anomalous_only=True, config=EventConfig())
    except ValueError as exc:
        assert "Label is intentionally not used" in str(exc)
    else:
        raise AssertionError("Label-only inputs must not create operational attack events.")

    predicted = raw.assign(**{"Predicted Anomaly": True})
    events = build_attack_events(predicted, anomalous_only=True)
    assert len(events) == 1
    assert int(events.iloc[0]["flow_count"]) == 3
    assert events.iloc[0]["detection_reasons"] == "ISOLATION_FOREST_ANOMALY"


def test_explicit_correlation_table_is_the_incident_formation_input():
    flows = pd.DataFrame([
        {
            "timestamp": _time(0), "src_ip": "A", "dst_ip": "B", "protocol": 6,
            "src_port": 50000, "dst_port": 22, "alert": True,
            "detection_reasons": "BRUTE_FORCE_PATTERN", "alert_sources": "BEHAVIOURAL_RULE",
        },
        {
            "timestamp": _time(1), "src_ip": "B", "dst_ip": "C", "protocol": 6,
            "src_port": 22, "dst_port": 445, "alert": True,
            "detection_reasons": "HIGH_SOURCE_FANOUT", "alert_sources": "BEHAVIOURAL_RULE",
        },
    ])
    events = build_soc_events(flows)
    correlations = EventCorrelationAgent(events, max_gap_seconds=300).correlate()
    assert not correlations.empty
    assert correlations["relation"].str.contains("host_pivot").any()

    formed = IncidentFormationAgent(events, correlations).form()
    assert len(formed) == 1
    assert set(formed[0][1]) == {"event:EVT-000001", "event:EVT-000002"}

    disconnected = IncidentFormationAgent(
        events,
        correlations.iloc[0:0],
    ).form()
    # The standalone brute-force candidate is retained; the isolated
    # context-only event is not promoted into an incident.
    assert len(disconnected) == 1
    assert set(disconnected[0][1]) == {"event:EVT-000001"}


def test_model_detection_reason_is_added_exactly_once_for_all_alert_combinations():
    rows = []

    # Ten destination ports for A -> B trigger PORT_SCAN and model alert.
    for port in range(2000, 2010):
        rows.append({
            "timestamp": _time(0),
            "src_ip": "A",
            "dst_ip": "B",
            "src_port": 40000 + port,
            "dst_port": port,
            "protocol": 6,
            "anomaly_score": 0.01,
        })

    # Isolated model-only flow.
    rows.append({
        "timestamp": _time(0),
        "src_ip": "C",
        "dst_ip": "D",
        "src_port": 41000,
        "dst_port": 80,
        "protocol": 6,
        "anomaly_score": 0.01,
    })

    # Ten destination ports for E -> F trigger a rule without a model alert.
    for port in range(3000, 3010):
        rows.append({
            "timestamp": _time(0),
            "src_ip": "E",
            "dst_ip": "F",
            "src_port": 42000 + port,
            "dst_port": port,
            "protocol": 6,
            "anomaly_score": 0.5,
        })

    result = merge_detector_outputs(
        pd.DataFrame(rows),
        anomaly_threshold=0.1,
    )

    model_reason = "ISOLATION_FOREST_ANOMALY"
    for index in range(10):
        tokens = result.loc[index, "detection_reasons"].split(";")
        assert tokens.count(model_reason) == 1
        assert result.loc[index, "review_reasons"] == "PORT_SCAN"
        assert result.loc[index, "review_alert"]
        assert not result.loc[index, "rule_alert"]
        assert result.loc[index, "model_alert"]
        assert result.loc[index, "alert"]

    model_only_index = 10
    model_only_tokens = result.loc[model_only_index, "detection_reasons"].split(";")
    assert model_only_tokens == [model_reason]
    assert not result.loc[model_only_index, "rule_alert"]
    assert result.loc[model_only_index, "model_alert"]
    assert result.loc[model_only_index, "alert"]

    for index in range(11, 21):
        tokens = result.loc[index, "detection_reasons"].split(";")
        assert tokens == [""]
        assert result.loc[index, "review_reasons"] == "PORT_SCAN"
        assert result.loc[index, "review_alert"]
        assert not result.loc[index, "rule_alert"]
        assert not result.loc[index, "model_alert"]
        assert not result.loc[index, "alert"]
        assert result.loc[index, "review_candidate"]

def test_low_precision_behaviours_are_context_only_and_not_alerts():
    rows = []

    # One source reaches several destinations on the same service.
    for number in range(4):
        rows.append({
            "timestamp": _time(0),
            "src_ip": "10.0.0.1",
            "dst_ip": f"10.0.1.{number + 1}",
            "src_port": 40000 + number,
            "dst_port": 80,
            "protocol": 6,
        })

    # Many sources send multiple flows to one destination.
    for source in range(3):
        for attempt in range(2):
            rows.append({
                "timestamp": _time(0, second=10 + attempt),
                "src_ip": f"10.0.2.{source + 1}",
                "dst_ip": "10.0.3.1",
                "src_port": 41000 + source * 10 + attempt,
                "dst_port": 443,
                "protocol": 6,
            })

    thresholds = BehaviourThresholds(
        source_fanout_unique_targets=3,
        horizontal_scan_unique_targets=3,
        ddos_unique_sources=3,
        ddos_min_flows=4,
    )
    result = detect_behavioral_alerts(pd.DataFrame(rows), thresholds)

    assert not result["rule_alert"].any()
    assert not result["review_alert"].any()
    assert result["detection_reasons"].eq("").all()
    assert result["context_signals"].str.contains(
        "HIGH_SOURCE_FANOUT"
    ).any()
    assert result["context_signals"].str.contains(
        "HORIZONTAL_SCAN"
    ).any()
    assert result["context_signals"].str.contains(
        "DISTRIBUTED_DOS_PATTERN"
    ).any()
    assert result["matched_rule_reasons"].ne("").any()


def test_port_scan_is_secondary_review_candidate_not_primary_alert():
    rows = pd.DataFrame([
        {
            "timestamp": _time(0),
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.9",
            "src_port": 40000 + port,
            "dst_port": port,
            "protocol": 6,
            "anomaly_score": 0.5,
        }
        for port in range(2000, 2012)
    ])

    result = merge_detector_outputs(rows, anomaly_threshold=0.1)
    assert result["review_alert"].all()
    assert result["review_candidate"].all()
    assert not result["rule_alert"].any()
    assert not result["model_alert"].any()
    assert not result["alert"].any()
    assert result["review_reasons"].str.contains("PORT_SCAN").all()

def test_saved_prediction_replay_skips_model_refit(tmp_path):
    rows = pd.DataFrame([
        {
            "timestamp": _time(0, second),
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.9",
            "src_port": 40000 + second,
            "dst_port": 22,
            "protocol": 6,
            "anomaly_score": 0.5,
            "predicted_anomaly": False,
            "split": "test",
            "label": "BENIGN",
        }
        for second in range(12)
    ])
    predictions = tmp_path / "saved_predictions.csv"
    output = tmp_path / "soc_replay"
    rows.to_csv(predictions, index=False)

    run_pipeline(PipelineConfig(
        output_dir=str(output),
        reuse_predictions=str(predictions),
    ))

    summary = json.loads(
        (output / "pipeline_summary.json").read_text(encoding="utf-8")
    )
    assert summary["replay_mode"] is True
    assert summary["model_refit"] is False
    assert summary["model_alert_flows"] == 0
    assert summary["behavioural_rule_alert_flows"] == 12
    assert summary["combined_alert_flows"] == 12
    assert summary["soc_investigation"]["incident_count"] == 1
    assert (output / "review_candidates_with_metadata.csv").exists()
    assert (output / "incident_investigation_report.md").exists()


def _event(event_id, minute, src, dst, port=443, reasons="ISOLATION_FOREST_ANOMALY"):
    timestamp = pd.Timestamp(_time(minute), tz="UTC")
    return {
        "event_id": event_id,
        "start_time": timestamp,
        "end_time": timestamp,
        "src_ip": src,
        "dst_ip": dst,
        "protocol": "6",
        "flow_count": 1,
        "dst_ports": [port],
        "detection_reasons": reasons,
        "review_reasons": "",
        "context_signals": "",
    }


def _edge(source, target, relation, gap=0):
    return {
        "from_event": source,
        "to_event": target,
        "relation": relation,
        "gap_seconds": gap,
        "overlap_seconds": 0,
        "shared_entity": None,
        "pivot_host": None,
    }


def test_same_service_and_same_target_links_do_not_form_incidents():
    events = pd.DataFrame([
        _event("E1", 0, "A", "B", 443),
        _event("E2", 0, "C", "D", 443),
        _event("E3", 0, "X", "B", 8443),
    ])
    correlations = pd.DataFrame([
        _edge("E1", "E2", "same_service_temporal", 0),
        _edge("E1", "E3", "same_target_temporal", 0),
    ])

    formed = IncidentFormationAgent(events, correlations).form()

    assert formed == []


def test_incident_formation_uses_only_short_same_source_and_host_pivot_edges():
    events = pd.DataFrame([
        _event("E1", 0, "A", "B"),
        _event("E2", 0, "A", "C"),
        _event("E3", 0, "B", "D"),
    ])
    correlations = pd.DataFrame([
        _edge("E1", "E2", "same_source_temporal", 30),
        _edge("E2", "E3", "host_pivot", 60),
    ])

    formed = IncidentFormationAgent(events, correlations).form()

    assert len(formed) == 1
    assert formed[0][1] == {"event:E1", "event:E2", "event:E3"}


def test_incident_formation_caps_transitive_campaign_duration():
    events = pd.DataFrame([
        _event(f"E{i:02d}", minute=i, src="A", dst=f"D{i}")
        for i in range(17)
    ])
    correlations = pd.DataFrame([
        _edge(f"E{i:02d}", f"E{i+1:02d}", "same_source_temporal", 60)
        for i in range(16)
    ])

    formed = IncidentFormationAgent(
        events,
        correlations,
        max_campaign_duration_seconds=900,
    ).form()

    assert len(formed) == 1
    assert len(formed[0][1]) == 16
    assert formed[0][2]["start_time"].min() == pd.Timestamp(_time(0), tz="UTC")
    assert (
        formed[0][2]["end_time"].max()
        - formed[0][2]["start_time"].min()
    ).total_seconds() == 900


def test_singleton_anomaly_is_not_incident_but_brute_force_candidate_is():
    events = pd.DataFrame([
        _event("ANOMALY", 0, "A", "B"),
        _event("BRUTE", 1, "C", "D", 22, "BRUTE_FORCE_PATTERN"),
    ])

    formed = IncidentFormationAgent(
        events,
        pd.DataFrame(columns=[
            "from_event", "to_event", "relation", "gap_seconds",
            "overlap_seconds", "shared_entity", "pivot_host"
        ]),
    ).form()

    assert len(formed) == 1
    assert formed[0][1] == {"event:BRUTE"}


def test_network_only_triage_cannot_claim_high_confidence_or_critical_severity():
    rows = pd.DataFrame({
        "detection_reasons": ["ISOLATION_FOREST_ANOMALY"] * 20,
        "review_reasons": [""] * 20,
    })
    graph_data = {
        "max_source_fanout": 100,
        "max_target_fanin": 100,
        "unique_services": 100,
        "graph_event_links": 500,
        "pivot_hosts": ["A"],
    }

    triage = __import__(
        "attack_graph.soc_investigation",
        fromlist=["IncidentTriageAgent"],
    ).IncidentTriageAgent.score(rows, graph_data, [], 0.5)

    assert triage["confidence"] == "LOW"
    assert triage["severity"] == "MEDIUM"
    assert triage["independent_signal_count"] == 0
    assert triage["priority_score"] == triage["risk_score"]


def test_two_external_telemetry_categories_can_raise_confidence():
    rows = pd.DataFrame({
        "detection_reasons": ["BRUTE_FORCE_PATTERN"] * 4,
        "review_reasons": [""] * 4,
        "external_evidence_sources": ["EDR;IDENTITY"] * 4,
    })
    graph_data = {
        "max_source_fanout": 2,
        "max_target_fanin": 2,
        "unique_services": 1,
        "graph_event_links": 1,
        "pivot_hosts": [],
    }

    from attack_graph.soc_investigation import IncidentTriageAgent
    triage = IncidentTriageAgent.score(rows, graph_data, [], 0.5)

    assert triage["confidence"] == "HIGH"
    assert triage["external_corroboration_sources"] == ["EDR", "IDENTITY"]


def test_t1021_requires_remote_service_port_on_exact_inbound_pivot_edge():
    from attack_graph.soc_investigation import ThreatHuntingAgent

    rows = pd.DataFrame([
        _event("A1", 0, "SRC", "PIVOT", 80),
        _event("A2", 1, "PIVOT", "DEST", 443),
        _event("B1", 2, "OTHER", "HOST", 80),
        _event("B2", 3, "HOST", "DEST2", 443),
        _event("UNRELATED", 4, "X", "Y", 3389),
    ])
    graph_data = {
        "pivot_hosts": ["PIVOT", "HOST"],
        "destination_ports": [80, 443, 3389],
        "chain_edges": [
            {
                "from_event": "A1", "to_event": "A2",
                "relation": "host_pivot", "pivot_host": "PIVOT",
                "gap_seconds": 60,
            },
            {
                "from_event": "B1", "to_event": "B2",
                "relation": "host_pivot", "pivot_host": "HOST",
                "gap_seconds": 60,
            },
        ],
    }

    hypotheses = ThreatHuntingAgent.analyse(rows, graph_data)
    remote = [item for item in hypotheses if item["technique_id"] == "T1021"]

    assert remote == []


def test_t1021_evidence_contains_only_exact_remote_service_pivot_pair():
    from attack_graph.soc_investigation import ThreatHuntingAgent

    rows = pd.DataFrame([
        _event("IN", 0, "SRC", "PIVOT", 22),
        _event("OUT", 1, "PIVOT", "DEST", 443),
        _event("UNRELATED", 2, "X", "Y", 3389),
    ])
    graph_data = {
        "pivot_hosts": ["PIVOT"],
        "destination_ports": [22, 443, 3389],
        "chain_edges": [
            {
                "from_event": "IN", "to_event": "OUT",
                "relation": "host_pivot", "pivot_host": "PIVOT",
                "gap_seconds": 60,
            },
        ],
    }

    hypotheses = ThreatHuntingAgent.analyse(rows, graph_data)
    remote = [item for item in hypotheses if item["technique_id"] == "T1021"]

    assert len(remote) == 1
    assert remote[0]["evidence_event_ids"] == ["IN", "OUT"]
    assert remote[0]["evidence_edges"][0]["remote_service_ports"] == [22]
