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

from .event_builder import EventConfig, build_attack_events, normalize_columns
from .graph_builder import add_sequence_edges, build_attack_graph, write_attack_graph_gexf


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
# Full-precision threshold stored in isolation_forest.ipynb. The notebook
# displays this as 0.032042 after rounding to six decimals.
FINAL_THRESHOLD = 0.032042255237655096
MAX_TRAIN_SAMPLES = 500_000

# Runtime versions used by the Colab 2026.07 environment associated with the
# benchmark execution. IsolationForest can change numerically across
# scikit-learn versions even with identical data/parameters/random_state.
BENCHMARK_ENVIRONMENT = {
    "python": "3.12.13",
    "scikit-learn": "1.6.1",
    "numpy": "2.0.2",
    "pandas": "2.2.2",
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

    # Deduplicate on the benchmark's 78 columns (69 final + 8 constants + Label).
    # Metadata columns are deliberately excluded so the deduplication semantics
    # match the no-metadata preprocessing notebook.
    raw_numeric = BENCHMARK_FEATURES + sorted(CONSTANT_FEATURES)
    dedup_columns = [c for c in raw_numeric if c in work.columns] + ["label"]
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

    # Build the 69-feature matrix. This follows the benchmark notebook:
    # numeric conversion, +/-inf -> NaN, then whole-dataset median fill.
    x = pd.DataFrame(index=work.index)
    for col in BENCHMARK_FEATURES:
        x[col] = pd.to_numeric(work[col], errors="coerce")

    x = x.replace([np.inf, -np.inf], np.nan)
    x = x.fillna(x.median(numeric_only=True))

    # Keep the cleaned 69-feature values in the preserved metadata table too.
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

    X = df.drop(columns=["Label"])
    y = (df["Label"].astype(str).str.strip() != "Benign").astype(int)

    if X.shape[1] != len(BENCHMARK_FEATURES):
        raise ValueError(
            f"Benchmark Parquet must contain exactly {len(BENCHMARK_FEATURES)} "
            f"features; found {X.shape[1]}"
        )

    # The notebook keeps CICIDS column spelling (e.g. "Flow Duration"),
    # whereas this integration file uses lowercase canonical names. Normalize
    # names only; do not reorder the Parquet columns, because column position is
    # part of exact model reproduction.
    parquet_feature_names = [str(c).strip().lower() for c in X.columns]
    if parquet_feature_names != BENCHMARK_FEATURES:
        missing = [c for c in BENCHMARK_FEATURES if c not in parquet_feature_names]
        extra = [c for c in parquet_feature_names if c not in BENCHMARK_FEATURES]
        raise ValueError(
            "Benchmark Parquet feature order/set does not match the expected "
            f"69-feature benchmark layout. Missing={missing}; Extra={extra}"
        )
    X.columns = parquet_feature_names

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

    model = IsolationForest(
        n_estimators=FINAL_N_ESTIMATORS,
        max_samples=FINAL_MAX_SAMPLES,
        max_features=FINAL_MAX_FEATURES,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train_benign_sample)

    val_scores = model.decision_function(X_val)
    test_scores = model.decision_function(X_test)

    val_metrics = evaluate(y_val, val_scores, FINAL_THRESHOLD)
    test_metrics = evaluate(y_test, test_scores, FINAL_THRESHOLD)

    environment = benchmark_environment_status()

    expected = {
        "roc_auc": 0.8862,
        "pr_auc": 0.6801,
        "precision": 0.6386,
        "recall": 0.7250,
        "f1": 0.6791,
        "fpr": 0.0729,
    }
    reproduction_check = {
        metric: {
            "actual": float(test_metrics[metric]),
            "expected_notebook": expected[metric],
            "absolute_delta": float(abs(test_metrics[metric] - expected[metric])),
            "matches_4dp": round(test_metrics[metric], 4) == expected[metric],
        }
        for metric in expected
    }

    result = {
        "dataset_rows": int(len(df)),
        "feature_count": int(X.shape[1]),
        "train_rows": int(len(X_train)),
        "validation_rows": int(len(X_val)),
        "test_rows": int(len(X_test)),
        "benign_training_sample": int(len(X_train_benign_sample)),
        "n_estimators": FINAL_N_ESTIMATORS,
        "max_samples": FINAL_MAX_SAMPLES,
        "max_features": FINAL_MAX_FEATURES,
        "contamination": "auto",
        "random_state": 42,
        "benchmark_threshold": FINAL_THRESHOLD,
        "environment": environment,
        "validation": val_metrics,
        "test": test_metrics,
        "reproduction_check_against_notebook_output": reproduction_check,
        "exact_4dp_reproduction": all(
            item["matches_4dp"] for item in reproduction_check.values()
        ),
    }

    (out / "exact_benchmark_reproduction.json").write_text(
        json.dumps(result, indent=2),
        encoding="utf-8",
    )

    print("\nEXACT BENCHMARK REPRODUCTION")
    print("=" * 60)
    print(f"Rows                : {len(df):,}")
    print(f"Features            : {X.shape[1]}")
    print(f"Train / Val / Test  : {len(X_train):,} / {len(X_val):,} / {len(X_test):,}")
    print(f"Benign train sample : {len(X_train_benign_sample):,}")
    print(f"Threshold           : {FINAL_THRESHOLD:.6f}")
    print(
        "Environment         :",
        "MATCH" if environment["matches"] else "MISMATCH",
    )
    if not environment["matches"]:
        for package, detail in environment["mismatches"].items():
            print(
                f"  {package}: installed={detail['installed']!r}, "
                f"expected={detail['expected']!r}"
            )
    print(f"ROC-AUC             : {test_metrics['roc_auc']:.4f}")
    print(f"PR-AUC              : {test_metrics['pr_auc']:.4f}")
    print(f"Precision           : {test_metrics['precision']:.4f}")
    print(f"Recall              : {test_metrics['recall']:.4f}")
    print(f"F1                  : {test_metrics['f1']:.4f}")
    print(f"FPR                 : {test_metrics['fpr']:.4f}")
    print(
        "Exact 4-decimal reproduction:",
        "YES" if result["exact_4dp_reproduction"] else "NO",
    )

    return result


def run(
    data_dir: str,
    output_dir: str,
    benchmark_parquet: str | None = None,
    verify_only: bool = False,
) -> None:
    start = time.time()

    if benchmark_parquet:
        exact_result = reproduce_exact_benchmark(
            benchmark_parquet,
            str(Path(output_dir) / "benchmark_verification"),
        )
        print(
            "\nBenchmark verification status:",
            "EXACT" if exact_result["exact_4dp_reproduction"] else "MISMATCH",
        )
        if verify_only:
            return
    data_path = Path(data_dir)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    df, x = exact_preprocess(load_metadata_dataset(data_path))

    print(f"Cleaned metadata-preserving rows: {len(df):,}")
    print(f"Benchmark features: {x.shape[1]}")

    indices = np.arange(len(df))
    y = df["is_attack"]

    train_idx, temp_idx = train_test_split(
        indices,
        test_size=0.30,
        random_state=42,
        stratify=y,
    )
    val_idx, test_idx = train_test_split(
        temp_idx,
        test_size=0.50,
        random_state=42,
        stratify=y.iloc[temp_idx],
    )

    train_attack = y.iloc[train_idx]
    train_benign_frame = pd.DataFrame({
        "_row_idx": train_idx,
        "_is_attack": train_attack.to_numpy(),
    })
    train_benign_frame = train_benign_frame[train_benign_frame["_is_attack"] == 0]

    # Match isolation_forest.ipynb exactly: pandas.DataFrame.sample(...,
    # random_state=42), not numpy choice.
    if len(train_benign_frame) > MAX_TRAIN_SAMPLES:
        train_benign_frame = train_benign_frame.sample(
            n=MAX_TRAIN_SAMPLES,
            random_state=42,
        )
    train_benign_idx = train_benign_frame["_row_idx"].to_numpy()

    print(f"Train rows     : {len(train_idx):,}")
    print(f"Validation rows: {len(val_idx):,}")
    print(f"Test rows      : {len(test_idx):,}")
    print(f"Benign IF train: {len(train_benign_idx):,}")

    model = IsolationForest(
        n_estimators=FINAL_N_ESTIMATORS,
        max_samples=FINAL_MAX_SAMPLES,
        max_features=FINAL_MAX_FEATURES,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )
    if benchmark_parquet:
        # The exact benchmark model was already fit in the verification helper;
        # retrain here from the same exact Parquet sample so metadata scoring
        # uses the identical benchmark training recipe.
        benchmark_df = pd.read_parquet(benchmark_parquet)
        benchmark_X = benchmark_df.drop(columns=["Label"])
        benchmark_y = (
            benchmark_df["Label"].astype(str).str.strip() != "Benign"
        ).astype(int)
        benchmark_feature_names = [str(c).strip().lower() for c in benchmark_X.columns]
        if benchmark_feature_names != BENCHMARK_FEATURES:
            missing = [c for c in BENCHMARK_FEATURES if c not in benchmark_feature_names]
            extra = [c for c in benchmark_feature_names if c not in BENCHMARK_FEATURES]
            raise ValueError(
                "Benchmark Parquet feature order/set does not match the expected "
                f"69-feature benchmark layout. Missing={missing}; Extra={extra}"
            )
        benchmark_X.columns = benchmark_feature_names
        X_train, _, y_train, _ = train_test_split(
            benchmark_X,
            benchmark_y,
            test_size=0.30,
            random_state=42,
            stratify=benchmark_y,
        )
        X_train_benign = X_train[y_train == 0]
        X_train_benign_sample = X_train_benign.sample(
            n=MAX_TRAIN_SAMPLES,
            random_state=42,
        )
        model.fit(X_train_benign_sample)
    else:
        model.fit(x.iloc[train_benign_idx])

    if benchmark_parquet:
        # Benchmark quality was already evaluated on the exact Parquet test set.
        # Do not present a metadata-CSV split evaluation as benchmark performance.
        val_metrics = None
        test_metrics = exact_result["test"]
    else:
        val_scores = model.decision_function(x.iloc[val_idx])
        test_scores = model.decision_function(x.iloc[test_idx])

        val_metrics = evaluate(y.iloc[val_idx], val_scores, FINAL_THRESHOLD)
        test_metrics = evaluate(y.iloc[test_idx], test_scores, FINAL_THRESHOLD)

        print("\nVALIDATION")
        print(json.dumps(val_metrics, indent=2))
        print("\nTEST")
        print(json.dumps(test_metrics, indent=2))

    # Score every cleaned flow using the model trained only on training BENIGN rows.
    all_scores = model.decision_function(x)
    df["anomaly_score"] = all_scores
    df["predicted_anomaly"] = all_scores < FINAL_THRESHOLD
    split = np.full(len(df), "train", dtype=object)
    split[val_idx] = "validation"
    split[test_idx] = "test"
    df["split"] = split

    predictions_path = out / "cicids_if_predictions_with_metadata.csv"
    df.to_csv(predictions_path, index=False)

    suspicious = df[df["predicted_anomaly"] & (df["label"].str.lower() != "benign")].copy()
    suspicious_path = out / "suspicious_flows_with_metadata.csv"
    suspicious.to_csv(suspicious_path, index=False)

    events = build_attack_events(
        suspicious,
        anomalous_only=True,
        config=EventConfig(time_window_seconds=60),
    )
    events.to_csv(out / "attack_events.csv", index=False)

    graph = build_attack_graph(events)
    graph = add_sequence_edges(graph, events)

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
        "benign_training_sample": int(len(train_benign_idx)),
        "n_estimators": FINAL_N_ESTIMATORS,
        "max_samples": FINAL_MAX_SAMPLES,
        "max_features": FINAL_MAX_FEATURES,
        "benchmark_threshold": FINAL_THRESHOLD,
        "benchmark_verification": exact_result if benchmark_parquet else None,
        "validation": val_metrics,
        "test": test_metrics,
        "metadata_scoring_all_flagged_flows": int(df["predicted_anomaly"].sum()),
        "metadata_scoring_non_benign_suspicious_flows": int(len(suspicious)),
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
    print(f"All flagged flows:        {df['predicted_anomaly'].sum():,}")
    print(f"Non-BENIGN suspicious:    {len(suspicious):,}")
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
