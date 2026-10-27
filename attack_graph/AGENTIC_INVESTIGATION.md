# Agentic AI Investigation

This module adds an optional LLM investigation step on top of the current
CICIDS2017 event table and NetworkX/GEXF attack graph. It does not replace
the Isolation Forest, event builder, graph builder, or existing deterministic
investigator.

## What it does

- Selects one event by its `event_id`.
- Retrieves nearby events within a configurable time window when they share
  the target event's source IP or destination IP.
- Reads predecessor/successor nodes and edge metadata for that event from
  `attack_graph.gexf`, when supplied.
- Optionally attaches a risk-assessment record from a JSON file.
- Calls an OpenAI model to return structured findings: summary, observed
  evidence, hypotheses with evidence/confidence, timeline, risk rationale,
  defensive next steps, and limitations.
- Writes a JSON evidence bundle and a Markdown report.
- Provides `--offline` mode for deterministic evidence summary/testing without
  an API call. Offline output is explicitly labelled as non-LLM output.

The investigator prompt treats dataset fields as untrusted data and instructs
the model not to infer attacker identity, successful compromise, data theft, or
root cause without supporting evidence. It does not execute containment actions.

## Install

From the repository root, with the project's regular environment active:

```powershell
python -m pip install -r requirements-agentic.txt
```

LLM mode requires an API key. Set it in the current PowerShell session; don't
commit the key to the repository:

```powershell
$env:OPENAI_API_KEY = "your-api-key"
$env:OPENAI_MODEL = "gpt-4.1-mini"
```

## Run an offline smoke test

Use a real event ID from your own `attack_events.csv`:

```powershell
python -m attack_graph.agentic_investigator "benchmark_graph_output/attack_events.csv" --event-id EVT-00001 --graph "benchmark_graph_output/attack_graph.gexf" --offline --output-dir "agentic_investigation_output"
```

## Run the LLM investigation

```powershell
python -m attack_graph.agentic_investigator "benchmark_graph_output/attack_events.csv" --event-id EVT-00001 --graph "benchmark_graph_output/attack_graph.gexf" --output-dir "agentic_investigation_output"
```

If risk assessment is available later as JSON keyed by event ID, pass it with
`--risk-json path/to/risk_assessment.json`.

Outputs:
- `agentic_investigation_<EVENT_ID>.json`
- `agentic_investigation_<EVENT_ID>.md`

The model's hypotheses are analyst aids, not verified ground truth. Review the
cited evidence before acting on any recommendation. Event IDs must exist in the
provided `attack_events.csv`; choose one from the file rather than assuming
`EVT-00001` always exists.
