# ML-Based Cyber-Attack Detection and SOC Incident Investigation

This repository implements one connected incident lifecycle for CICIDS2017 flow telemetry. Use `attack_graph.pipeline` as the canonical entry point. The old prototype detector and old incident-investigator commands are compatibility adapters; they no longer run separate detection or triage algorithms.

## Canonical end-to-end flow

```text
CICIDS2017 CSVs
  -> Schema validation and metadata-preserving preprocessing
  -> Train-only imputation and Isolation Forest fitting
  -> Validation-calibrated anomaly scores
  -> Independent behavioural detections
  -> Unified alert records (model/rule provenance + evidence)
  -> Temporal and entity correlation
  -> Candidate incident formation
  -> Incident-linked attack graph
  -> Incident-level risk and confidence
  -> Read-only investigation tools
  -> Evidence-linked findings and recommended SOC actions
  -> JSON / CSV / GEXF / Markdown report
```

Each stage consumes the previous stage's output contract. `incident_id` links the incident dossier to its event IDs, the graph's incident node, risk assessment, agent tool calls and final report. `event_correlations.csv` preserves the relationship type, time gap, shared entity and host-pivot evidence. `soc_pipeline_manifest.json` records stage completion, counts and generated artefacts.

## Run the canonical pipeline

Create the environment:

    python -m venv .venv-benchmark
    .\.venv-benchmark\Scripts\Activate.ps1
    python -m pip install --upgrade pip
    python -m pip install -r requirements-benchmark.txt

Run on the eight metadata-rich CICIDS2017 CSV files:

    python -m attack_graph.pipeline "D:\MAJOR PROJECT\cicids_metadata\generated_flows" --output-dir "soc_output"

To replay an updated detector policy and SOC investigation using an existing prediction artefact without retraining Isolation Forest:

    python -m attack_graph.pipeline --reuse-predictions "soc_output\\cicids_if_predictions_with_metadata.csv" --output-dir "soc_output_policy_v2"

Replay mode requires the saved `predicted_anomaly` flags. It reuses the original model outputs, reruns behavioural rule policy and rebuilds the downstream event, graph and incident artefacts. It does not refit Isolation Forest or recalculate model performance metrics.

To additionally verify the historical notebook benchmark before running the SOC pipeline:

    python -m attack_graph.pipeline "D:\MAJOR PROJECT\cicids_metadata\generated_flows" --benchmark-parquet "D:\MAJOR PROJECT\cleaned_cicids2017.parquet" --output-dir "soc_output"

To run only the historical benchmark verifier:

    python -m attack_graph.pipeline "D:\MAJOR PROJECT\cicids_metadata\generated_flows" --benchmark-parquet "D:\MAJOR PROJECT\cleaned_cicids2017.parquet" --output-dir "soc_output" --verify-only

`if_attack_graph_pipeline.py` is a backward-compatible alias to the canonical pipeline. Its old independent prototype flow has been retired. `incident_investigator.py` is also a compatibility adapter; it imports legacy event CSVs into the shared event contract and invokes the same graph, risk and investigation workflow.

## Pipeline component contracts

| Stage | Input | Output / responsibility |
|---|---|---|
| Ingestion and preprocessing | CICIDS2017 CSVs | Canonical columns; preserve timestamp/IP/port/protocol metadata; fit imputation only on training rows |
| ML detection | 69-feature flow matrix | Isolation Forest anomaly score and model alert provenance |
| Behaviour detection | Timestamp, endpoints, ports, protocol and flow metadata | Explainable scan, fan-out, DDoS-pattern and authentication-service rule signals |
| Alert fusion | Model and behavioural outputs | One alert decision per flow; `alert_sources` and `detection_reasons` |
| Event correlation | Alert flows | Events grouped by endpoint pair/protocol/time; graph relations record shared source, target, service and host pivots |
| Incident formation | Correlated event graph | Connected candidate incident groups with stable incident IDs in the run |
| Attack graph | Events and correlation relations | Typed host, event, service, detection and incident nodes; incident-to-event membership edges |
| Risk assessment | Incident event set and graph metrics | Transparent priority score, severity and confidence; score is not a compromise probability |
| Investigation agent | Incident dossier plus read-only tools | Incident, event timeline, graph neighbourhood and detection-provenance retrieval; tool trace and evidence-linked findings |
| Reporting | Full structured incident context | Incident CSV/JSON, correlation CSV, GEXF, Markdown and stage manifest |

### Behavioural detections and alert policy

All behavioural rules are computed independently of the CICIDS ground-truth `Label`. Their output is separated into three tiers based on the observed validation results from this dataset:

| Rule | Default condition within a 5-minute bucket | Current policy tier |
|---|---|---|
| Brute-force pattern | At least 12 flows from one source to one destination on a common authentication port | Actionable rule candidate |
| Port scan | One source probes at least 10 destination ports on one destination | Secondary analyst-review queue |
| High source fan-out | One source communicates with at least 15 distinct destinations | Context only |
| Horizontal scan | One source probes at least 10 distinct destinations on the same destination port | Context only |
| Distributed DoS pattern | One destination receives at least 40 flows from at least 15 distinct sources | Context only |

The current policy combines Isolation Forest alerts with the brute-force rule for primary incident selection. Port-scan-only rows are written to `review_candidates_with_metadata.csv` and do not independently create incidents. The remaining weak heuristics are retained in `context_signals` / `matched_rule_reasons` for evidence and offline analysis, but do not independently raise alerts or create ATT&CK hypotheses.

This is a provisional CICIDS2017 benchmark policy, not a production-calibrated rule set. The observed validation precision/false-positive rates motivated the tiering; thresholds and policy must be revalidated on representative operational telemetry. Fixed time buckets can miss behaviour crossing a boundary; streaming deployment needs stateful rolling windows and network-specific calibration.

### Correlation and incident formation

Event correlation is a distinct stage implemented by `EventCorrelationAgent`. It emits an inspectable relationship table before incident formation, linking events independently by shared source, shared destination, shared destination service and target-to-source host pivots. `IncidentFormationAgent` consumes this table and groups connected event components into candidate incidents. Only then is the incident-linked attack graph assembled, with a first-class incident node and `contains` edges to member events. The exact edge types, shared entities, time gaps and overlaps are retained in `event_correlations.csv`.

### Risk assessment

The priority score combines detection-rule diversity, event persistence, source fan-out, destination convergence, service diversity and relative anomaly rank only when Isolation Forest actually fired for that incident. Severity is derived from the heuristic score. Confidence reflects independent evidence types and event support. Neither is a calibrated probability of compromise.

### Tool-driven investigation

`AgenticInvestigationAgent` first retrieves the incident, chronological timeline, graph neighbourhood and detector provenance. It then exposes a bounded read-only tool registry: `get_event`, `get_host_activity`, `get_service_activity` and `get_correlated_events`. A reasoner can select up to five additional tools in one round. Every call records arguments, result summaries, status and event references. Model findings are accepted only when they cite event IDs inside the current incident; unsupported or cross-incident claims are rejected.

The default mode is a deterministic, tool-assisted baseline. The existing local LLM/Ollama reasoner can be passed as a Python callback in `PipelineConfig(reasoner=...)`; the callback receives an evidence bundle and tool catalogue, and should return structured JSON containing `tool_calls`, `findings` and `narrative` to enable model-directed tool use. Plain text responses are treated as narrative-only. This keeps your model/server/runtime configuration separate from the SOC orchestration code. No Ollama server/model settings are changed by this refactor.

To run the canonical dataset pipeline with the reasoner function you already use for Ollama, pass that existing callable to the configuration instead of starting a second workflow:

    from attack_graph.pipeline import PipelineConfig, run_pipeline
    run_pipeline(PipelineConfig(
        data_dir=r"D:\MAJOR PROJECT\cicids_metadata\generated_flows",
        output_dir="soc_output",
        reasoner=your_existing_ollama_reasoner,
    ))

The callback contract is `reasoner(context: dict) -> str | dict`. For model-directed tool use, return a dictionary with `tool_calls` (up to five allowlisted calls), `findings` (each with valid `evidence_event_ids`) and `narrative`. A plain string is accepted as narrative-only.

## Output artefacts

| File | Contents |
|---|---|
| `cicids_if_predictions_with_metadata.csv` | Flow-level model scores, rule flags and unified alert decision |
| `suspicious_flows_with_metadata.csv` | Primary Isolation Forest OR actionable brute-force rule alerts, including benign-labelled false positives |
| `review_candidates_with_metadata.csv` | Port-scan-only secondary review candidates; not promoted into primary incidents |
| `attack_events.csv` | Primary-alert event records with detection, review and context provenance |
| `event_correlations.csv` | Event-to-event relationship evidence, time gaps and pivot hosts |
| `attack_graph.gexf` | Incident-linked graph for Gephi or compatible viewers |
| `incident_investigation.csv` | Event-to-incident assignments and incident-level triage |
| `incident_investigation.json` | Structured incident dossiers, graph findings, tool calls and evidence-linked findings |
| `incident_investigation_report.md` | SOC analyst investigation report |
| `soc_pipeline_manifest.json` | Stage sequence, status, counts and output artefacts |
| `pipeline_summary.json` | Model, detector, graph and incident metrics |

## Data and research limitations

CICIDS2017 provides labelled network flows, timestamps, endpoints, ports, protocols and flow-level traffic statistics. It does not by itself provide authentication success/failure logs, operating-system process execution, privilege changes or file-access telemetry. Therefore this flow-only system can identify network-level patterns and candidate ATT&CK hypotheses, but it cannot prove a chain such as failed login -> successful login -> privilege escalation -> sensitive file access -> exfiltration without additional identity, endpoint and application data sources.

Ground-truth labels remain available for offline benchmark evaluation, not operational alert selection, event correlation, incident grouping, graph construction, risk scoring or agent findings. The historical exact benchmark verifier intentionally retains notebook preprocessing for reproduction and must not be confused with the leakage-safe metadata SOC pipeline.

## Research evaluation

Compare incremental configurations on the same held-out data and report detection metrics, incident reconstruction metrics and analyst-investigation quality separately:

1. Detection only.
2. Detection + event correlation.
3. Detection + correlation + attack graph + incident risk.
4. Full system + tool-driven investigation.

Useful incident metrics include event-to-incident assignment precision/recall, pairwise event-link precision/recall, incident detection delay, duplicate-incident rate and evidence coverage. LLM output quality should be evaluated for factual support, citation coverage, unsupported claims and analyst usefulness rather than judged only by report length.

## Tests

    python -m pip install pytest
    pytest -q

GitHub Actions runs Python compilation and the focused integration tests on each push and pull request.