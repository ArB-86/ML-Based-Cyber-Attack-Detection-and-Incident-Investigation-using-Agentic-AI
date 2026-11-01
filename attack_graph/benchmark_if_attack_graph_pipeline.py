from __future__ import annotations

import argparse
import importlib.metadata as metadata
import json
import platform
import time
from pathlib import Path

import networkx as nx
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from .event_builder import normalize_columns
from .graph_builder import write_attack_graph_gexf
from .soc_detection import merge_detector_outputs
from .soc_investigation import run_soc_investigation


LABEL_MAP = {
    "Web Attack \x96 Brute Force": "Web Attack - Brute Force",
    "Web Attack \x96 XSS": "Web Attack - XSS",
    "Web Attack \x96 Sql Injection": "Web Attack - SQL Injection",
    "Web Attack \uFFFD Brute Force": "Web Attack - Brute Force",
    "Web Attack \uFFFD XSS": "Web Attack - XSS",
    "Web Attack \uFFFD Sql Injection": "Web Attack - SQL Injection",
}

# Exact 69 numeric features used by isolation_forest.ipynb after the
# preprocessing notebook removed eight constant columns.
BENCHMARK_FEATURES = [
    "protocol",
    "flow duration",
    "total fwd packets",
    "total backward packets",
    "fwd packets length total",
    "bwd packets length total",
    "fwd packet length max",
    "fwd packet length min",
    "fwd packet length mean",
    "fwd packet length std",
    "bwd packet length max",
    "bwd packet length min",
    "bwd packet length mean",
    "bwd packet length std",
    "flow bytes/s",
    "flow packets/s",
    "flow iat mean",
    "flow iat std",
    "flow iat max",
    "flow iat min",
    "fwd iat total",
    "fwd iat mean",
    "fwd iat std",
    "fwd iat max",
    "fwd iat min",
    "bwd iat total",
    "bwd iat mean",
    "bwd iat std",
    "bwd iat max",
    "bwd iat min",
    "fwd psh flags",
    "fwd urg flags",
    "fwd header length",
    "bwd header length",
    "fwd packets/s",
    "bwd packets/s",
    "packet length min",
    "packet length max",
    "packet length mean",
    "packet length std",
    "packet length variance",
    "fin flag count",
    "syn flag count",
    "rst flag count",
    "psh flag count",
    "ack flag count",
    "urg flag count",
    "cwe flag count",
    "ece flag count",
    "down/up ratio",
    "avg packet size",
    "avg fwd segment size",
    "avg bwd segment size",
    "subflow fwd packets",
    "subflow fwd bytes",
    "subflow bwd packets",
    "subflow bwd bytes",
    "init fwd win bytes",
    "init bwd win bytes",
    "fwd act data packets",
    "fwd seg size min",
    "active mean",
    "active std",
    "active max",
    "active min",
    "idle mean",
    "idle std",
    "idle max",
    "idle min",
]

CONSTANT_FEATURES = {
    "bwd psh flags",
    "bwd urg flags",
    "fwd avg bytes/bulk",
    "fwd avg packets/bulk",
    "fwd avg bulk rate",
    "bwd avg bytes/bulk",
    "bwd avg packets/bulk",
    "bwd avg bulk rate",
}

INVALID_NEGATIVE_FEATURES = [
    "flow duration",
    "flow bytes/s",
    "flow packets/s",
    "flow iat mean",
    "flow iat max",
    "flow iat min",
    "fwd iat min",
    "fwd header length",
    "bwd header length",
    "fwd seg size min",
]

SENTINEL_FEATURES = ["init fwd win bytes", "init bwd win bytes"]

# The preprocessing notebook's Parquet group order. The metadata-rich CSV
# files are mapped to these same logical groups to preserve the benchmark
# row-order convention as closely as possible.
CSV_ORDER = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
]

FINAL_N_ESTIMATORS = 200
FINAL_MAX_SAMPLES = 1024
FINAL_MAX_FEATURES = 1.0
# Threshold displayed by the fresh Colab execution of isolation_forest.ipynb.
# The notebook prints six decimal places; no unsupported hidden precision is
# assumed here.
FINAL_THRESHOLD = 0.032849
MAX_TRAIN_SAMPLES = 500_000

# Runtime versions observed in the fresh Colab execution used as the current
# benchmark reference.
BENCHMARK_ENVIRONMENT = {
    "python": "3.13.15",
    "scikit-learn": "1.6.1",
    "numpy": "2.1.3",
    "pandas": "2.2.3",
    "scipy": "1.16.3",
    "pyarrow": "18.1.0",
    "joblib": "1.5.3",
}


def benchmark_environment_status() -> dict:
    current = {"python": platform.python_version()}
    for package in BENCHMARK_ENVIRONMENT:
        if package == "python":
            continue
        try:
            current[package] = metadata.version(package)
        except metadata.PackageNotFoundError:
            current[package] = None

    mismatches = {
        package: {
            "expected": expected,
            "installed": current.get(package),
        }
        for package, expected in BENCHMARK_ENVIRONMENT.items()
        if current.get(package) != expected
    }
    return {
        "expected": BENCHMARK_ENVIRONMENT,
        "installed": current,
        "matches": not mismatches,
        "mismatches": mismatches,
    }


def _resolve_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Canonicalize CICIDS column names while preserving the metadata columns
    expected by the downstream event/graph builders.

    The raw metadata-rich CSV exports use title-cased names such as
    "Ack Flag Count" and "Flow Duration". The benchmark feature list is
    stored in lowercase canonical form, so all normalized column names are
    lowercased first. A small alias map then handles known naming variants.
    """
    out = normalize_columns(df).copy()
    out.columns = [str(c).strip().lower() for c in out.columns]

    aliases = {
        "fwd packets length total": [
            "fwd packets length total",
            "total length of fwd packets",
        ],
        "bwd packets length total": [
            "bwd packets length total",
            "total length of bwd packets",
        ],
        "packet length min": [
            "packet length min",
            "min packet length",
        ],
        "packet length max": [
            "packet length max",
            "max packet length",
        ],
        "avg packet size": [
            "avg packet size",
            "average packet size",
        ],
        "init fwd win bytes": [
            "init fwd win bytes",
            "init_win_bytes_forward",
            "init win bytes forward",
        ],
        "init bwd win bytes": [
            "init bwd win bytes",
            "init_win_bytes_backward",
            "init win bytes backward",
        ],
        "fwd act data packets": [
            "fwd act data packets",
            "act_data_pkt_fwd",
            "act data pkt in fwd dir",
        ],
        "fwd seg size min": [
            "fwd seg size min",
            "min_seg_size_forward",
            "min seg size forward",
        ],
    }

    rename = {}
    for canonical, candidates in aliases.items():
        if canonical in out.columns:
            continue
        actual = next((candidate for candidate in candidates if candidate in out.columns), None)
        if actual is not None and actual != canonical:
            rename[actual] = canonical

    if rename:
        out = out.rename(columns=rename)

    return out


def load_metadata_dataset(data_dir: Path) -> pd.DataFrame:
    frames = []
    missing_files = []

    for filename in CSV_ORDER:
        path = data_dir / filename
        if not path.exists():
            missing_files.append(filename)
            continue

        print(f"Loading: {filename}")
        frame = pd.read_csv(
            path,
            low_memory=False,
            encoding="latin1",
        )
        frame = _resolve_columns(frame)

        if "label" not in frame.columns:
            raise ValueError(f"Missing Label column in {filename}")

        frame["label"] = frame["label"].astype(str).str.strip().replace(LABEL_MAP)
        frames.append(frame)

    if missing_files:
        raise FileNotFoundError(
            "Missing expected metadata-rich CSV files: " + ", ".join(missing_files)
        )

    if not frames:
        raise FileNotFoundError(f"No expected CSV files found in {data_dir}")

    return pd.concat(frames, ignore_index=True)


def exact_preprocess(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Mirror dataset_preprocessing.ipynb while preserving metadata columns."""
    work = _resolve_columns(df).copy()

    # Match the notebook's Label normalization.
    work["label"] = work["label"].astype(str).str.strip().replace(LABEL_MAP)

    # Only columns that survive into the final 69-feature matrix are mandatory
    # for model inference. The eight benchmark-constant columns are optional
    # because some metadata-rich exports omit them entirely; the preprocessing
    # result is still identical for the 69-feature model.
    missing = [c for c in BENCHMARK_FEATURES if c not in work.columns]
    if missing:
        raise ValueError(f"Missing benchmark preprocessing columns: {sorted(set(missing))}")

    # The benchmark Parquet verifier preserves the notebook's feature-only
    # deduplication for historical reproduction. The metadata SOC path must
    # retain distinct hosts, ports and timestamps even when feature vectors
    # match, otherwise repeated activity and graph pivots disappear.
    raw_numeric = BENCHMARK_FEATURES + sorted(CONSTANT_FEATURES)
    metadata_columns = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port"]
    dedup_columns = (
        [c for c in raw_numeric if c in work.columns]
        + [c for c in metadata_columns if c in work.columns]
        + ["label"]
    )
    before = len(work)
    work = work.drop_duplicates(subset=dedup_columns, keep="first").reset_index(drop=True)
    print(f"Rows before deduplication: {before:,}")
    print(f"Rows after deduplication : {len(work):,}")
    print(f"Removed duplicates       : {before - len(work):,}")

    invalid_mask = pd.Series(False, index=work.index)
    for col in INVALID_NEGATIVE_FEATURES:
        invalid_mask |= pd.to_numeric(work[col], errors="coerce") < 0

    removed_invalid = int(invalid_mask.sum())
    work = work.loc[~invalid_mask].reset_index(drop=True)
    print(f"Removed invalid-negative rows: {removed_invalid:,}")

    for col in SENTINEL_FEATURES:
        work[col] = pd.to_numeric(work[col], errors="coerce").replace(-1, np.nan)

    # Remove the exact eight constant columns when they are present.
    constant_present = [c for c in sorted(CONSTANT_FEATURES) if c in work.columns]
    work = work.drop(columns=constant_present)

    # Keep missing values here. The metadata pipeline fits medians on the
    # training partition only, then applies those medians to validation/test.
    # The separate exact-benchmark verifier intentionally mirrors the legacy
    # notebook so historical metrics remain reproducible.
    x = pd.DataFrame(index=work.index)
    for col in BENCHMARK_FEATURES:
        x[col] = pd.to_numeric(work[col], errors="coerce")

    x = x.replace([np.inf, -np.inf], np.nan)

    # Preserve the un-imputed numeric features in the metadata frame.
    for col in BENCHMARK_FEATURES:
        work[col] = x[col]

    work["is_attack"] = work["label"].str.lower().ne("benign").astype(int)
    return work, x


def evaluate(y_true: pd.Series, scores: np.ndarray, threshold: float) -> dict:
    pred = (scores < threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred).ravel()
    return {
        "roc_auc": float(roc_auc_score(y_true, -scores)),
        "pr_auc": float(average_precision_score(y_true, -scores)),
        "precision": float(precision_score(y_true, pred, zero_division=0)),
        "recall": float(recall_score(y_true, pred, zero_division=0)),
        "f1": float(f1_score(y_true, pred, zero_division=0)),
        "fpr": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "threshold": threshold,
        "flagged": int(pred.sum()),
    }



def reproduce_exact_benchmark(parquet_path: str, output_dir: str) -> dict:
    """
    Reproduce isolation_forest.ipynb on the exact cleaned CICIDS2017 Parquet.

    This is the authoritative benchmark verification path. The Parquet is
    already the output of dataset_preprocessing.ipynb, so no second
    preprocessing pass is applied here. Split order, benign sampling,
    Isolation Forest hyperparameters, threshold, and metrics mirror the
    benchmark notebook.
    """
    path = Path(parquet_path)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    if not path.exists():
        raise FileNotFoundError(f"Benchmark Parquet not found: {path}")

    print(f"Loading benchmark Parquet: {path}")
    df = pd.read_parquet(path)

    if "Label" not in df.columns:
        raise ValueError("Benchmark Parquet must contain a 'Label' column")

    X = df.drop(columns=["Label"]).copy()
    y = (df["Label"].astype(str).str.strip() != "Benign").astype(int)

    if X.shape[1] != len(BENCHMARK_FEATURES):
        raise ValueError(
            f"Benchmark Parquet must contain exactly {len(BENCHMARK_FEATURES)} "
            f"features; found {X.shape[1]}"
        )

    # Keep the Parquet feature order, then mirror the preprocessing performed
    # in isolation_forest.ipynb after loading the cleaned Parquet:
    # +/-inf -> NaN, followed by whole-dataset median imputation.
    parquet_feature_names = [str(c).strip().lower() for c in X.columns]
    if parquet_feature_names != BENCHMARK_FEATURES:
        missing = [c for c in BENCHMARK_FEATURES if c not in parquet_feature_names]
        extra = [c for c in parquet_feature_names if c not in BENCHMARK_FEATURES]
        raise ValueError(
            "Benchmark Parquet feature order/set does not match the expected "
            f"69-feature benchmark layout. Missing={missing}; Extra={extra}"
        )
    X.columns = parquet_feature_names

    X = X.replace([np.inf, -np.inf], np.nan)
    if X.isna().sum().sum() > 0:
        X = X.fillna(X.median(numeric_only=True))

    constant_cols = X.columns[X.nunique() <= 1].tolist()
    if constant_cols:
        X = X.drop(columns=constant_cols)

    if X.shape[1] != len(BENCHMARK_FEATURES):
        raise ValueError(
            "Isolation Forest preprocessing changed the feature count: "
            f"expected {len(BENCHMARK_FEATURES)}, found {X.shape[1]}"
        )

    X_train, X_temp, y_train, y_temp = train_test_split(
        X,
        y,
        test_size=0.30,
        random_state=42,
        stratify=y,
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp,
        y_temp,
        test_size=0.50,
        random_state=42,
        stratify=y_temp,
    )

    X_train_benign = X_train[y_train == 0]
    X_train_benign_sample = X_train_benign.sample(
        n=MAX_TRAIN_SAMPLES,
        random_state=42,
    )

    model_training_sample = len(train_benign_idx)
    model = IsolationForest(
        n_estimators=FINAL_N_ESTIMATORS,
        max_samples=FINAL_MAX_SAMPLES,
        max_features=FINAL_MAX_FEATURES,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(x.iloc[train_benign_idx])
    model_training_sample = len(train_benign_idx)

    # The exact notebook verifier above remains a separate historical
    # reproduction. Regardless of whether its Parquet was supplied, the SOC
    # run trains and calibrates on the metadata pipeline's own split.
    val_scores = model.decision_function(x.iloc[val_idx])
    test_scores = model.decision_function(x.iloc[test_idx])
    validation_benign = y.iloc[val_idx].to_numpy() == 0
    if not validation_benign.any():
        raise ValueError("Validation split contains no benign rows for threshold calibration.")
    # Set a 5% benign validation alert budget. Never optimise this threshold
    # against attack labels or use the test split for threshold selection.
    active_threshold = float(np.quantile(val_scores[validation_benign], 0.05))
    val_metrics = evaluate(y.iloc[val_idx], val_scores, active_threshold)
    test_metrics = evaluate(y.iloc[test_idx], test_scores, active_threshold)

    print("\nVALIDATION (5% benign-tail threshold calibration)")
    print(json.dumps(val_metrics, indent=2))
    print("\nHELD-OUT TEST")
    print(json.dumps(test_metrics, indent=2))

    # Isolation Forest is one detector in a broader alert pipeline.
    all_scores = model.decision_function(x)
    df["anomaly_score"] = all_scores
    df["predicted_anomaly"] = all_scores < active_threshold
    split = np.full(len(df), "train", dtype=object)
    split[val_idx] = "validation"
    split[test_idx] = "test"
    df["split"] = split

    df = merge_detector_outputs(df, anomaly_threshold=active_threshold)
    predictions_path = out / "cicids_if_predictions_with_metadata.csv"
    df.to_csv(predictions_path, index=False)

    # Do not intersect with Label != Benign. Doing so hides false positives
    # and leaks benchmark ground truth into the operational investigation.
    suspicious = df[df["alert"]].copy()
    suspicious_path = out / "suspicious_flows_with_metadata.csv"
    suspicious.to_csv(suspicious_path, index=False)

    # The SOC workflow owns event formation, typed graph construction,
    # temporal/pivot correlation, ATT&CK hypotheses, triage and reporting.
    events, graph, investigation_summary = run_soc_investigation(suspicious, out)

    gexf_path = out / "attack_graph.gexf"
    gexf_written = False
    try:
        write_attack_graph_gexf(graph, str(gexf_path))
        gexf_written = gexf_path.exists() and gexf_path.stat().st_size > 0
    except Exception as exc:
        print(f"GEXF write failed: {exc}")

    png_status = "skipped"
    if graph.number_of_nodes() > 0 and graph.number_of_nodes() <= 800:
        try:
            import matplotlib.pyplot as plt

            pos = nx.spring_layout(graph, seed=42)
            plt.figure(figsize=(12, 8))
            nx.draw_networkx(
                graph,
                pos,
                node_size=120,
                with_labels=False,
                arrows=True,
                alpha=0.6,
            )
            plt.title("CICIDS2017 Attack Graph - Benchmark Isolation Forest")
            plt.axis("off")
            plt.tight_layout()
            plt.savefig(out / "attack_graph.png", dpi=160)
            plt.close()
            png_status = "full"
        except Exception as exc:
            print(f"PNG generation skipped: {exc}")
    elif graph.number_of_nodes() > 800:
        try:
            import matplotlib.pyplot as plt

            rng = np.random.default_rng(42)
            nodes = list(graph.nodes())
            sample_nodes = rng.choice(nodes, size=800, replace=False)
            sub = graph.subgraph(sample_nodes)
            pos = nx.spring_layout(sub, seed=42)
            plt.figure(figsize=(12, 8))
            nx.draw_networkx(
                sub,
                pos,
                node_size=80,
                with_labels=False,
                arrows=True,
                alpha=0.6,
            )
            plt.title(
                f"CICIDS2017 Attack Graph - sample 800/{graph.number_of_nodes()} nodes"
            )
            plt.axis("off")
            plt.tight_layout()
            plt.savefig(out / "attack_graph.png", dpi=160)
            plt.close()
            png_status = f"capped_sample_800_of_{graph.number_of_nodes()}"
        except Exception as exc:
            print(f"PNG generation skipped: {exc}")

    summary = {
        "cleaned_rows": int(len(df)),
        "feature_count": int(x.shape[1]),
        "train_rows": int(len(train_idx)),
        "validation_rows": int(len(val_idx)),
        "test_rows": int(len(test_idx)),
        "model_training_sample": int(model_training_sample),
        "n_estimators": FINAL_N_ESTIMATORS,
        "max_samples": FINAL_MAX_SAMPLES,
        "max_features": FINAL_MAX_FEATURES,
        "benchmark_threshold": FINAL_THRESHOLD,
        "benchmark_verification": exact_result if benchmark_parquet else None,
        "validation": val_metrics,
        "test": test_metrics,
        "model_alert_flows": int(df["model_alert"].sum()),
        "behavioural_rule_alert_flows": int(df["rule_alert"].sum()),
        "combined_alert_flows": int(df["alert"].sum()),
        "alert_flows_investigated": int(len(suspicious)),
        "ground_truth_used_for_alert_selection": False,
        "soc_investigation": investigation_summary,
        "attack_events": int(len(events)),
        "graph_nodes": int(graph.number_of_nodes()),
        "graph_edges": int(graph.number_of_edges()),
        "gexf_written": bool(gexf_written),
        "png_status": png_status,
        "elapsed_seconds": round(time.time() - start, 2),
    }
    (out / "pipeline_summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    print("\nDONE")
    print(f"Isolation Forest alerts:  {df['model_alert'].sum():,}")
    print(f"Behavioural rule alerts:  {df['rule_alert'].sum():,}")
    print(f"Combined SOC alerts:      {df['alert'].sum():,}")
    print(f"Alert flows investigated: {len(suspicious):,}")
    print(f"Candidate incidents:      {investigation_summary['incident_count']:,}")
    print(f"Attack events:            {len(events):,}")
    print(f"Graph nodes:              {graph.number_of_nodes():,}")
    print(f"Graph edges:              {graph.number_of_edges():,}")
    print(f"Elapsed seconds:          {time.time() - start:.2f}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "data_dir",
        help="Folder containing the eight metadata-rich CICIDS2017 CSV files",
    )
    parser.add_argument(
        "--output-dir",
        default="benchmark_graph_output",
    )
    parser.add_argument(
        "--benchmark-parquet",
        default=None,
        help=(
            "Exact cleaned_cicids2017.parquet used by isolation_forest.ipynb. "
            "When supplied, the script verifies the benchmark reproduction and "
            "uses the same benchmark training recipe for metadata scoring."
        ),
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help=(
            "Run only the exact benchmark reproduction against --benchmark-parquet; "
            "do not load metadata CSVs or build the attack graph."
        ),
    )
    args = parser.parse_args()
    run(
        args.data_dir,
        args.output_dir,
        args.benchmark_parquet,
        args.verify_only,
    )
