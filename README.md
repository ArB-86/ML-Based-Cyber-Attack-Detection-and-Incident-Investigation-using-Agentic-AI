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

For the closest local reproduction, use the Python/package versions documented in `requirements-benchmark.txt`. Exact numerical agreement should be checked in the same Colab runtime used for the reference; Windows is the integration environment:

```powershell
python -m venv .venv-benchmark
.\.venv-benchmark\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-benchmark.txt
```

The verifier prints the installed package versions and flags any environment mismatch before showing the benchmark comparison. Exact numerical agreement should be checked in the same Colab runtime used for the reference; Windows runs are useful for integration validation but may differ numerically across Python/NumPy/platform builds.
