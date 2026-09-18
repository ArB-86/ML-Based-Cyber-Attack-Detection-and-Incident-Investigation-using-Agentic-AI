from __future__ import annotations

import argparse
import json
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
FINAL_THRESHOLD = 0.032042
MAX_TRAIN_SAMPLES = 500_000


def _resolve_columns(df: pd.DataFrame) -> pd.DataFrame:
    out = normalize_columns(df)
    normalized = {str(c).strip().lower(): c for c in out.columns}

    aliases = {
        "fwd packets length total": ["fwd packets length total", "total length of fwd packets"],
        "bwd packets length total": ["bwd packets length total", "total length of bwd packets"],
        "packet length min": ["packet length min", "min packet length"],
        "packet length max": ["packet length max", "max packet length"],
        "avg packet size": ["avg packet size", "average packet size"],
        "init fwd win bytes": ["init fwd win bytes", "init_win_bytes_forward", "init win bytes forward"],
        "init bwd win bytes": ["init bwd win bytes", "init_win_bytes_backward", "init win bytes backward"],
        "fwd act data packets": ["fwd act data packets", "act_data_pkt_fwd", "act data pkt in fwd dir"],
        "fwd seg size min": ["fwd seg size min", "min_seg_size_forward", "min seg size forward"],
    }

    rename = {}
    for canonical, candidates in aliases.items():
        actual = next((normalized[c] for c in candidates if c in normalized), None)
        if actual is not None and actual != canonical:
            rename[actual] = canonical

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
    dedup_columns = raw_numeric + ["label"]
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

    # Remove the exact eight constant columns from the benchmark representation.
    work = work.drop(columns=sorted(CONSTANT_FEATURES))

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


def run(data_dir: str, output_dir: str) -> None:
    start = time.time()
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
    train_benign_idx = train_idx[train_attack.to_numpy() == 0]
    if len(train_benign_idx) > MAX_TRAIN_SAMPLES:
        rng = np.random.RandomState(42)
        train_benign_idx = rng.choice(
            train_benign_idx,
            size=MAX_TRAIN_SAMPLES,
            replace=False,
        )

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
    model.fit(x.iloc[train_benign_idx])

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
        "validation": val_metrics,
        "test": test_metrics,
        "all_flagged_flows": int(df["predicted_anomaly"].sum()),
        "non_benign_suspicious_flows": int(len(suspicious)),
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
    args = parser.parse_args()
    run(args.data_dir, args.output_dir)
