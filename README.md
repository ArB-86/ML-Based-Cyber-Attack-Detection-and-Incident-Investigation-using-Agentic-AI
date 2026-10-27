# ML-Based-Cyber-Attack-Detection-and-Incident-Investigation-using-Agentic-AI

## Benchmark verification and attack-graph integration

Use the exact `cleaned_cicids2017.parquet` produced by `dataset_preprocessing.ipynb` to reproduce the Isolation Forest benchmark before running the metadata attack-graph integration.

```powershell
python -m attack_graph.benchmark_if_attack_graph_pipeline "D:\MAJOR PROJECT\cicids_metadata\generated_flows" --benchmark-parquet "D:\MAJOR PROJECT\cleaned_cicids2017.parquet" --output-dir "benchmark_graph_output" --verify-only
```

The verification path mirrors `isolation_forest.ipynb`: 69 features, 70/15/15 stratified split with `random_state=42`, 500,000 benign training rows selected with `DataFrame.sample(..., random_state=42)`, Isolation Forest with 200 trees and `max_samples=1024`, and the fresh Colab threshold displayed as `0.032849`. The current fresh Colab reference metrics are ROC-AUC `0.8876`, PR-AUC `0.6843`, Precision `0.6388`, Recall `0.7252`, F1 `0.6792`, and FPR `0.0729`. The verifier writes `exact_benchmark_reproduction.json`. When Python/NumPy/pandas versions differ from the reference runtime, it reports `REFERENCE_ONLY_RUNTIME_DIFFERENCE` rather than falsely claiming an exact reproduction.

To verify first and then build the metadata-preserving attack graph using the same benchmark-trained model:

```powershell
python -m attack_graph.benchmark_if_attack_graph_pipeline "D:\MAJOR PROJECT\cicids_metadata\generated_flows" --benchmark-parquet "D:\MAJOR PROJECT\cleaned_cicids2017.parquet" --output-dir "benchmark_graph_output"
```

## Agentic AI incident investigation

The optional `attack_graph.agentic_investigator` module builds on the existing event table and GEXF graph. It correlates nearby events, retrieves graph-neighborhood evidence, optionally accepts a risk-assessment JSON record, and can call an OpenAI model for a structured investigation. It distinguishes observed evidence from model hypotheses and states limitations rather than treating a dataset label as proof of successful compromise.

Install the optional dependency:

```powershell
python -m pip install -r requirements-agentic.txt
```

Set the API key only in your local terminal; never commit it to the repository:

```powershell
$env:OPENAI_API_KEY = "your-api-key"
$env:OPENAI_MODEL = "gpt-4.1-mini"
```

Run an offline smoke test with an event ID that actually exists in your events file. To list IDs first, use `python -c "import pandas as pd; print(pd.read_csv('benchmark_graph_output/attack_events.csv')['event_id'].head(10).to_list())"`:

```powershell
python -m attack_graph.agentic_investigator "benchmark_graph_output/attack_events.csv" --event-id EVT-00001 --graph "benchmark_graph_output/attack_graph.gexf" --offline --output-dir "agentic_investigation_output"
```

For live LLM investigation, omit `--offline`:

```powershell
python -m attack_graph.agentic_investigator "benchmark_graph_output/attack_events.csv" --event-id EVT-00001 --graph "benchmark_graph_output/attack_graph.gexf" --output-dir "agentic_investigation_output"
```

Optional risk assessment can later be attached with `--risk-json path/to/risk_assessment.json`. Outputs are `agentic_investigation_<EVENT_ID>.json` and `agentic_investigation_<EVENT_ID>.md`. Read [attack_graph/AGENTIC_INVESTIGATION.md](attack_graph/AGENTIC_INVESTIGATION.md) for details. Replace `EVT-00001` with an event ID actually present in `attack_events.csv`.

For the closest local reproduction, use the Python/package versions documented in `requirements-benchmark.txt`. Exact numerical agreement should be checked in the same Colab runtime used for the reference; Windows is the integration environment:

```powershell
python -m venv .venv-benchmark
.\.venv-benchmark\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-benchmark.txt
```

The verifier prints the installed package versions and flags environment mismatch before showing the benchmark comparison. Exact numerical agreement should be checked in the same Colab runtime used for the reference; Windows runs are useful for integration validation but may differ numerically across Python/NumPy/platform builds.
