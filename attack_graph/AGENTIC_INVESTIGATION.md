# Agentic AI Investigation

This module completes the investigation stage on top of the existing CICIDS2017 event table and NetworkX/GEXF attack graph. It does not replace or retrain the Isolation Forest, event builder, graph builder, or graph-generation pipeline.

## Investigation flow

1. Select an event ID that exists in the existing attack_events.csv.
2. Load the corresponding event node and the existing attack_graph.gexf.
3. Calculate deterministic graph evidence around the selected event: bounded multi-hop neighbourhood, shared source/destination host events, explicit temporal precedes sequence, connected component, attack-type cluster, source-to-destination structural paths and graph metrics.
4. Give an LLM a catalogue of allowlisted investigation tools. The model selects tools based on unresolved evidence questions.
5. Execute tool calls in Python, validate tool names, bound graph traversal and record tool arguments, purpose, status and findings.
6. Allow up to two planner rounds by default (maximum three). A deterministic baseline tool set runs if the local planner returns no valid first-round tool calls.
7. Pass the selected event, graph evidence, tool findings and trace to the final LLM report step.
8. Write a JSON evidence bundle and a Markdown SOC investigation report.

## Graph investigation tools

- get_event_details: retrieve exact event records by event ID.
- expand_graph_neighborhood: traverse incoming/outgoing graph relationships over multiple hops.
- find_shared_host_events: identify event nodes linked through the selected source/destination hosts.
- trace_temporal_sequence: trace only edges explicitly labelled precedes.
- summarize_connected_component: list the graph component containing the selected event.
- summarize_attack_type_cluster: inspect the event's attack-type node and linked events.
- find_structural_paths: inspect directed structural source-host to destination-host paths.
- summarize_graph_metrics: calculate local node/edge counts, relation and node-type counts, degrees and bounded betweenness centrality.

Tool calls are allowlisted and their execution trace is preserved in the JSON report. Traversal and result sizes are bounded to prevent unbounded graph expansion and excessively large LLM prompts.

## Evidence and interpretation guardrails

CICIDS2017 is network-flow telemetry. It does not, by itself, supply a complete authentication, identity, endpoint process, privilege-escalation, file-access or data-exfiltration audit trail. The investigator must report these as evidence gaps unless separate telemetry is supplied.

A shared host, attack-type node, connected component or directed graph path is structural evidence. None independently proves a confirmed campaign, compromise, attacker movement or operational impact. Temporal order is stated only when explicit precedes edges exist.

The Isolation Forest decision_function score is interpreted using the threshold belonging to the pipeline that produced the event table. The module prefers benchmark_threshold in pipeline_summary.json, then prototype_threshold_calibrated, and supports an explicit --threshold override. A score is an anomaly indicator, not a probability or incident-severity score.

## Install

From the repository root:

```powershell
python -m pip install -r requirements-agentic.txt
```

Install Ollama and download a local model:

```powershell
ollama pull qwen2.5:7b
ollama list
```

Local Ollama mode does not require an OpenAI API key or per-token API billing. Performance depends on local hardware.

## Run

Use a real event ID from the generated event table:

```powershell
python -m attack_graph.agentic_investigator "benchmark_graph_output/attack_events.csv" --event-id EVT-00001 --graph "benchmark_graph_output/attack_graph.gexf" --provider ollama --model qwen2.5:7b --output-dir "agentic_investigation_output"
```

The planner performs two rounds by default. Set --max-tool-rounds 1 for a shorter run or --max-tool-rounds 3 for a deeper bounded pass.

To run deterministic graph analysis without an LLM call, add --offline. Offline mode is not an agentic result.

OpenAI hosting is optional. Set OPENAI_API_KEY locally and explicitly pass --provider openai if using it; never commit the key.

## Outputs

- agentic_investigation_<EVENT_ID>.json — complete event evidence, graph overview, agent tool-call trace, tool findings and structured investigation.
- agentic_investigation_<EVENT_ID>.md — analyst-readable report with graph analysis and tool-use trace.
