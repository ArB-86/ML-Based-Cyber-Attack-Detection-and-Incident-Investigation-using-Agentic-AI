# ML-Based Cyber-Attack Detection and SOC Incident Investigation

This repository contains a CICIDS2017 Isolation Forest benchmark and an evidence-first SOC investigation pipeline. The operational workflow is designed to reconstruct related network activity from flow metadata instead of producing only a generic model summary.

## SOC workflow

1. Detection: Isolation Forest provides an unsupervised anomaly signal. Independent metadata-based behavioural rules can also raise alerts.
2. Event formation: detector alerts are grouped by source, destination, protocol and temporal proximity. The operational event builder does not use the CICIDS ground-truth Label column. Distinct source/destination IPs, ports and timestamps are retained during metadata-path deduplication, even when numeric flow features match.
3. Attack graph: typed host, event, service and detection nodes are connected through shared-source, shared-destination, shared-service and target-to-source host-pivot relationships.
4. SOC investigation: specialist stages analyse graph topology, create cautious MITRE ATT&CK hypotheses, score incident priority and produce evidence-backed response recommendations.
5. Reporting: CSV and JSON retain the evidence. The Markdown report includes a prioritised incident queue, source/target concentration, graph links, event timelines, ATT&CK hypotheses, caveats and analyst actions.

## Independent behavioural detections

The following rules complement Isolation Forest. They use timestamps, IP addresses, ports, protocol and flow metadata. They never inspect the Label column.

| Rule | Default condition within a 5-minute bucket |
|---|---|
| Port scan | One source probes at least 10 destination ports on one destination |
| Horizontal scan | One source probes at least 10 distinct destinations on the same destination port |
| High source fan-out | One source communicates with at least 15 distinct destinations |
| Distributed DoS pattern | One destination receives at least 40 flows from at least 15 distinct sources |
| Brute-force pattern | At least 12 flows from one source to one destination on a common authentication port |

These are transparent hunt heuristics, not calibrated classifiers. Fixed time buckets can miss activity crossing a bucket boundary. A streaming deployment should use stateful rolling windows and tune thresholds against the target network.

## Run the SOC pipeline

Create and activate the environment:

    python -m venv .venv-benchmark
    .\.venv-benchmark\Scripts\Activate.ps1
    python -m pip install --upgrade pip
    python -m pip install -r requirements-benchmark.txt

Run on the eight metadata-rich CICIDS2017 CSV files:

    python -m attack_graph.benchmark_if_attack_graph_pipeline "D:\MAJOR PROJECT\cicids_metadata\generated_flows" --output-dir "soc_output"

For the SOC run, imputation medians are fitted on training rows only. The Isolation Forest threshold is calibrated from the 5th percentile of held-out benign validation scores. The test partition is reserved for final evaluation; its labels do not select alerts or tune the threshold.

## Historical benchmark reproduction

The exact benchmark verifier is intentionally retained to check the original notebook reference numbers. Run it separately:

    python -m attack_graph.benchmark_if_attack_graph_pipeline "D:\MAJOR PROJECT\cicids_metadata\generated_flows" --benchmark-parquet "D:\MAJOR PROJECT\cleaned_cicids2017.parquet" --output-dir "soc_output" --verify-only

This historical verification path mirrors the original notebook, including its full-dataset median-imputation behavior. It is kept for reproducibility and must not be confused with the leakage-safe SOC training/evaluation path.

If you provide --benchmark-parquet without --verify-only, the benchmark is checked first and the operational SOC pipeline still trains and calibrates on the metadata pipeline's own split.

## Graph reasoning and incident triage

The graph adds independent links for repeated activity from a shared source, multiple sources converging on the same destination, events touching the same destination service, and a host that is first targeted and later initiates another related connection (a host-pivot lead). Connected event components become candidate incidents.

The triage score combines behavioural-rule diversity, persistence, source fan-out, destination convergence, service diversity and (when Isolation Forest actually raised an alert) relative anomaly rank. It is a heuristic priority score, not a probability of compromise.

ATT&CK mappings are hypotheses with evidence and caveats. Network probing may support a T1046 candidate, repeated authentication-service flows may support T1110, and converging traffic may support T1498. Flow records alone cannot confirm credential guessing, successful compromise, lateral movement or service impact.

## Output artefacts

| File | Contents |
|---|---|
| cicids_if_predictions_with_metadata.csv | Flow-level model scores, behavioural-rule flags and combined alert decision |
| suspicious_flows_with_metadata.csv | All model OR behavioural-rule alerts, including benign-labelled false positives |
| attack_events.csv | Detector-derived, metadata-preserving events |
| attack_graph.gexf | Typed graph for Gephi or another GEXF-compatible viewer |
| incident_investigation.csv | Event-to-incident assignments, triage and confidence |
| incident_investigation.json | Structured incident dossiers, graph metrics, timelines, ATT&CK hypotheses and response actions |
| incident_investigation_report.md | SOC analyst-oriented investigation report |
| pipeline_summary.json | Dataset, threshold, detector, graph and incident counts |

The alert-selection and investigation path does not use ground-truth labels. Labels remain available for offline evaluation only. The report documents limitations of benchmark flow data and requires analyst validation before containment.

## Ollama / local LLM

No Ollama integration is present in the tracked source files of this GitHub repository, so this change does not add, configure or alter Ollama, its model, server, prompts or latency. The structured incident JSON is ready to be consumed by a separate local-LLM layer if you have one in your local workspace. The LLM should explain those findings; it should not invent entities, attack chains, severity or ATT&CK mappings absent from the evidence JSON.

Important scope distinction: the graph analyst, threat-hunting and triage stages in this branch are deterministic, role-separated analysis modules. They form an auditable investigation workflow, not a claim that autonomous tool-using LLM agents are already implemented.

## Tests

Install pytest and run:

    python -m pip install pytest
    pytest -q

Focused tests cover label-independent detections, investigation of benign-labelled alerts, shared-target graph edges and host-pivot reconstruction.