# ML-Based-Cyber-Attack-Detection-and-Incident-Investigation-using-Agentic-AI

## Exact benchmark reproduction

Use the exact `cleaned_cicids2017.parquet` produced by `dataset_preprocessing.ipynb` to reproduce the Isolation Forest benchmark before running the metadata attack-graph integration.

```powershell
python -m attack_graph.benchmark_if_attack_graph_pipeline "D:\MAJOR PROJECT\cicids_metadata\generated_flows" --benchmark-parquet "D:\MAJOR PROJECT\cleaned_cicids2017.parquet" --output-dir "benchmark_graph_output" --verify-only
```

The verification path mirrors `isolation_forest.ipynb`: 69 features, 70/15/15 stratified split with `random_state=42`, 500,000 benign training rows selected with `DataFrame.sample(..., random_state=42)`, Isolation Forest with 200 trees and `max_samples=1024`, and threshold `0.032042`. It writes `exact_benchmark_reproduction.json` and reports whether all benchmark metrics match the notebook output to 4 decimal places.

To verify first and then build the metadata-preserving attack graph using the same benchmark-trained model:

```powershell
python -m attack_graph.benchmark_if_attack_graph_pipeline "D:\MAJOR PROJECT\cicids_metadata\generated_flows" --benchmark-parquet "D:\MAJOR PROJECT\cleaned_cicids2017.parquet" --output-dir "benchmark_graph_output"
```

For reproducible benchmark numbers on Windows, use the pinned environment in `requirements-benchmark.txt`:

```powershell
python -m venv .venv-benchmark
.\.venv-benchmark\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-benchmark.txt
```

The verifier prints the installed package versions and flags any environment mismatch before showing the benchmark comparison.
