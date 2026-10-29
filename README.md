# ML-Based-Cyber-Attack-Detection-and-Incident-Investigation-using-Agentic-AI

## Optional Agentic AI Investigation

The optional `attack_graph.agentic_investigator` module generates an evidence-grounded incident report for one event from the existing `attack_events.csv` and `attack_graph.gexf` outputs. It retrieves nearby events using a configurable time window and shared source/destination IPs, reads the event's graph neighborhood, and generates JSON and Markdown reports with a local Ollama model. It does not replace the existing detector or execute response actions.

Install the optional Python client (the existing pipeline already uses pandas and NetworkX):

```powershell
python -m pip install -r requirements-agentic.txt
ollama pull qwen2.5:7b
```

First run the existing attack-graph pipeline so its output directory contains `attack_events.csv` and `attack_graph.gexf`. Then list event IDs and run an investigation, replacing the example ID with one that exists in your output:

```powershell
Import-Csv "attack_graph_output\attack_events.csv" | Select-Object -First 10 event_id, attack_type
python -m attack_graph.agentic_investigator "attack_graph_output/attack_events.csv" --event-id EVT-00001 --graph "attack_graph_output/attack_graph.gexf" --provider ollama --model qwen2.5:7b --output-dir "agentic_investigation_output"
```

The module reads `prototype_threshold_calibrated` from a neighboring `pipeline_summary.json` when available. Use `--threshold VALUE` to override it; otherwise it uses a compatibility fallback threshold. Reports are written as `agentic_investigation_<EVENT_ID>.json` and `agentic_investigation_<EVENT_ID>.md`.

For a deterministic evidence-only smoke test without calling an LLM, add `--offline`. Offline mode is not an LLM/agentic result. Local LLM mode uses Ollama and does not require an OpenAI API key.
