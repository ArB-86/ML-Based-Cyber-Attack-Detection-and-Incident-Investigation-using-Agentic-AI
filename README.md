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

The Agentic Investigation module consumes the existing attack_events.csv and attack_graph.gexf outputs. It does not retrain the detector or rebuild the attack graph. The graph is the primary investigation input; event records provide the evidence behind graph nodes.

For a selected event, the module calculates a bounded multi-hop graph neighbourhood, shared-host event relationships, explicit temporal precedes sequences, connected-component membership, attack-type clusters, structural source-to-destination paths, and graph metrics. A local LLM selects from an allowlist of Python investigation tools. The runtime executes those tools, records every call and result, and permits up to two investigation-planning rounds by default before generating the final evidence-grounded SOC report.

The report includes the incident summary, graph findings, reconstructed network sequence when explicit temporal edges exist, involved hosts, hypotheses with evidence, confidence, risk rationale, evidence gaps, defensive next steps, limitations, and the tool-use trace. Graph paths describe structural connectivity and do not prove successful attacker movement or impact.

### Install and local model

Install the optional OpenAI-compatible Python client:

```powershell
python -m pip install -r requirements-agentic.txt
```

Install Ollama and download the local model:

```powershell
ollama pull qwen2.5:7b
ollama list
```

Local Ollama mode does not require an OpenAI API key or paid API usage. Inference runs on the local machine; speed depends on its hardware.

### Run an investigation

Use an event ID that exists in the generated event table:

```powershell
python -m attack_graph.agentic_investigator "benchmark_graph_output/attack_events.csv" --event-id EVT-00001 --graph "benchmark_graph_output/attack_graph.gexf" --provider ollama --model qwen2.5:7b --output-dir "agentic_investigation_output"
```

The agent performs up to two bounded tool-planning rounds by default. Use --max-tool-rounds 1 for a faster single-round pass, or --max-tool-rounds 3 for a deeper bounded pass. The threshold is read from the adjacent pipeline_summary.json using the pipeline-specific benchmark_threshold or prototype_threshold_calibrated field; --threshold VALUE explicitly overrides it.

For deterministic graph evidence without an LLM call, add --offline. Offline mode is graph analysis only and is not an agentic result.

OpenAI hosting is optional and explicitly selected. Keep OPENAI_API_KEY in the local environment, never commit it, and add --provider openai to the command. Hosted API usage may incur charges.

Outputs are agentic_investigation_<EVENT_ID>.json and agentic_investigation_<EVENT_ID>.md inside the selected output directory.


For the closest local reproduction, use the Python/package versions documented in `requirements-benchmark.txt`. Exact numerical agreement should be checked in the same Colab runtime used for the reference; Windows is the integration environment:

```powershell
python -m venv .venv-benchmark
.\.venv-benchmark\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-benchmark.txt
```

The verifier prints the installed package versions and flags environment mismatch before showing the benchmark comparison. Exact numerical agreement should be checked in the same Colab runtime used for the reference; Windows runs are useful for integration validation but may differ numerically across Python/NumPy/platform builds.
