from __future__ import annotations

import argparse
import time
from pathlib import Path

import networkx as nx
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from .event_builder import EventConfig, build_attack_events, normalize_columns
from .graph_builder import add_sequence_edges, build_attack_graph, write_attack_graph_gexf


LABEL_MAP = {
    "Web Attack \x96 Brute Force": "Web Attack - Brute Force",
    "Web Attack \x96 XSS": "Web Attack - XSS",
    "Web Attack \x96 Sql Injection": "Web Attack - SQL Injection",
    "Web Attack � Brute Force": "Web Attack - Brute Force",
    "Web Attack � XSS": "Web Attack - XSS",
    "Web Attack � Sql Injection": "Web Attack - SQL Injection",
}

META = {
    "flow id",
    "source ip",
    "source port",
    "destination ip",
    "destination port",
    "timestamp",
    "label",
    "is_attack",
    "predicted_anomaly",
    "anomaly_score",
}

# Reference only. This threshold belongs to the ORIGINAL project's Isolation
# Forest, trained on the cleaned CICIDS2017 Parquet (69 numeric features,
# 500k benign training sample, 200 trees). It is documented here for
# traceability and must NEVER be applied to scores from the prototype model
# below, which is trained on a different feature space (80 numeric features
# from the metadata-rich CSVs) and therefore has a different score
# distribution. Do not use this constant to threshold prototype scores.
BENCHMARK_ISOLATION_FOREST_THRESHOLD = 0.032042


def clean_labels(df: pd.DataFrame) -> pd.DataFrame:
    out = normalize_columns(df)
    out["label"] = (
        out["label"].astype(str).str.strip().replace(LABEL_MAP)
    )
    return out


def prepare_features(df: pd.DataFrame, feature_columns: list[str] | None = None):
    work = clean_labels(df)
    drop_cols = [c for c in work.columns if c.lower() in META]
    x = work.drop(columns=drop_cols, errors="ignore")

    x = x.select_dtypes(include=np.number).copy()
    x = x.replace([np.inf, -np.inf], np.nan)

    if feature_columns is None:
        feature_columns = x.columns.tolist()

    missing = [c for c in feature_columns if c not in x.columns]
    if missing:
        raise ValueError(f"Missing feature columns: {missing}")

    x = x[feature_columns]
    x = x.fillna(x.median(numeric_only=True))
    return work, x, feature_columns


def load_metadata_sample(data_dir: Path, nrows: int) -> pd.DataFrame:
    files = sorted(data_dir.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")

    frames = []
    for path in files:
        print(f"Loading: {path.name}")
        df = pd.read_csv(
            path,
            nrows=nrows,
            low_memory=False,
            encoding="latin1",
        )
        df = clean_labels(df)
        frames.append(df)

    return pd.concat(frames, ignore_index=True)


def run(
    data_dir: str,
    output_dir: str,
    nrows: int = 20_000,
    benign_sample_n: int = 10_000,
    n_estimators: int = 50,
    calibration_quantile: float = 0.05,
) -> None:
    """Run the Attack Graph prototype pipeline.

    calibration_quantile: fraction of a held-out BENIGN validation subset
    (not used for training) whose scores are treated as the "anomalous"
    tail. The prototype's anomaly threshold is calibrated as this
    quantile of held-out benign scores -- independent of the original
    project's 69-feature benchmark threshold.
    """
    t_start = time.time()
    data_path = Path(data_dir)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    df = load_metadata_sample(data_path, nrows=nrows)

    _, x, feature_columns = prepare_features(df)
    y = df["label"].astype(str)

    benign_mask = y.str.upper().eq("BENIGN")
    benign = x.loc[benign_mask]

    if benign.empty:
        raise ValueError("No BENIGN rows found for Isolation Forest training.")

    # Held-out split: train_benign fits the model, val_benign (unseen during
    # training) calibrates the prototype's own anomaly threshold. This keeps
    # calibration independent of both training data and the 69-feature
    # benchmark model.
    benign_shuffled = benign.sample(frac=1.0, random_state=42)
    n_val = max(1, int(0.2 * len(benign_shuffled)))
    val_benign = benign_shuffled.iloc[:n_val]
    train_benign_pool = benign_shuffled.iloc[n_val:]

    if train_benign_pool.empty:
        raise ValueError(
            "Not enough BENIGN rows to both train and hold out a "
            "validation subset for threshold calibration."
        )

    sample_n = min(benign_sample_n, len(train_benign_pool))
    benign_sample = train_benign_pool.sample(sample_n, random_state=42)

    print(f"Total sampled flows: {len(df):,}")
    print(f"Numeric features: {len(feature_columns)}")
    print(f"Benign training sample: {len(benign_sample):,}")
    print(f"Benign validation (held out, for threshold calibration): {len(val_benign):,}")

    # Prototype config (reduced compute). NOTE: this is NOT the final project
    # benchmark (200 trees, 500k benign sample) reported in isolation_forest.ipynb.
    # Keep that notebook/result untouched — this is a separate, clearly-labeled
    # prototype run for the metadata-rich CSV / attack-graph integration.
    model = IsolationForest(
        n_estimators=n_estimators,
        max_samples=1024,
        max_features=1.0,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(benign_sample)

    # sklearn: higher = more normal. Convert so lower = more anomalous,
    # matching the project's anomaly-score convention.
    df["anomaly_score"] = model.score_samples(x)

    # Calibrate the prototype's own threshold from held-out BENIGN scores
    # (never from the 69-feature benchmark). calibration_quantile fraction of
    # held-out benign flows fall below this threshold by construction.
    val_scores = model.score_samples(val_benign)
    prototype_threshold = float(np.quantile(val_scores, calibration_quantile))
    print(
        f"Prototype threshold (calibrated, {calibration_quantile:.0%} of held-out "
        f"benign scores): {prototype_threshold:.6f}"
    )
    print(
        f"[reference only, NOT used] original 69-feature benchmark threshold: "
        f"{BENCHMARK_ISOLATION_FOREST_THRESHOLD}"
    )

    df["predicted_anomaly"] = df["anomaly_score"] < prototype_threshold

    suspicious = df[df["predicted_anomaly"]].copy()
    suspicious.to_csv(out / "suspicious_flows_with_metadata.csv", index=False)

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

    # Lightweight PNG for inspection only. The full graph (any size) is
    # always saved to GEXF above for real analysis in Gephi/etc; this PNG
    # is just a quick visual sanity check. spring_layout is O(n^2)-ish per
    # iteration, so past a node-count cap we skip it (or draw a random
    # sample of the same graph) rather than let the prototype hang -- the
    # graph/event data itself is never altered because of this cap.
    max_png_nodes = 800
    n_nodes = graph.number_of_nodes()
    png_status = "skipped"

    if n_nodes == 0:
        print("PNG generation skipped: graph has no nodes.")
    elif n_nodes > max_png_nodes:
        print(
            f"PNG generation: {n_nodes:,} nodes exceeds cap ({max_png_nodes}); "
            "drawing a random subgraph sample instead of the full spring_layout."
        )
        try:
            import matplotlib.pyplot as plt

            rng = np.random.default_rng(42)
            sample_nodes = rng.choice(
                list(graph.nodes()), size=max_png_nodes, replace=False
            )
            sub = graph.subgraph(sample_nodes)
            pos = nx.spring_layout(sub, seed=42)
            plt.figure(figsize=(12, 8))
            nx.draw_networkx(
                sub, pos, node_size=80, with_labels=False, arrows=True, alpha=0.6
            )
            plt.title(
                f"CICIDS2017 Attack Graph - sample of {max_png_nodes:,}/"
                f"{n_nodes:,} nodes (full graph in attack_graph.gexf)"
            )
            plt.axis("off")
            plt.tight_layout()
            plt.savefig(out / "attack_graph.png", dpi=160)
            plt.close()
            png_status = f"capped_sample_{max_png_nodes}_of_{n_nodes}"
        except Exception as exc:
            print(f"PNG generation (sampled) skipped: {exc}")
    else:
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
            plt.title("CICIDS2017 Attack Graph - Isolation Forest Prototype")
            plt.axis("off")
            plt.tight_layout()
            plt.savefig(out / "attack_graph.png", dpi=160)
            plt.close()
            png_status = "full"
        except Exception as exc:
            print(f"PNG generation skipped: {exc}")

    elapsed_seconds = time.time() - t_start

    pd.Series(
        {
            "sampled_flows": int(len(df)),
            "suspicious_flows": int(suspicious["predicted_anomaly"].sum()),
            "attack_events": int(len(events)),
            "graph_nodes": int(graph.number_of_nodes()),
            "graph_edges": int(graph.number_of_edges()),
            "feature_count": int(len(feature_columns)),
            "gexf_written": bool(gexf_written),
            "png_status": png_status,
            "elapsed_seconds": round(elapsed_seconds, 2),
            "prototype_threshold_calibrated": prototype_threshold,
            "calibration_quantile": calibration_quantile,
            "benchmark_threshold_reference_only": BENCHMARK_ISOLATION_FOREST_THRESHOLD,
        }
    ).to_json(out / "pipeline_summary.json", indent=2)

    print("DONE")
    print(f"Suspicious flows: {len(suspicious):,}")
    print(f"Attack events:    {len(events):,}")
    print(f"Graph nodes:      {graph.number_of_nodes():,}")
    print(f"Graph edges:      {graph.number_of_edges():,}")
    print(f"GEXF written:     {gexf_written}")
    print(f"PNG status:       {png_status}")
    print(f"Elapsed seconds:  {elapsed_seconds:.2f}")
    print(f"Output folder:    {out}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "data_dir",
        help="Folder containing metadata-rich CICIDS2017 CSV files",
    )
    parser.add_argument(
        "--output-dir",
        default="attack_graph_output",
    )
    parser.add_argument(
        "--nrows",
        type=int,
        default=20_000,
        help="Rows read from each CSV for the prototype",
    )
    parser.add_argument(
        "--benign-sample-n",
        type=int,
        default=10_000,
        help="Benign flows sampled for Isolation Forest training",
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=50,
        help="Isolation Forest tree count for the prototype run",
    )
    parser.add_argument(
        "--calibration-quantile",
        type=float,
        default=0.05,
        help=(
            "Quantile of held-out BENIGN validation scores used as the "
            "prototype anomaly threshold (independent of the benchmark "
            "threshold)."
        ),
    )
    args = parser.parse_args()
    run(
        args.data_dir,
        args.output_dir,
        args.nrows,
        args.benign_sample_n,
        args.n_estimators,
        args.calibration_quantile,
    )
