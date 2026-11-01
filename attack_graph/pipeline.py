from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .benchmark_if_attack_graph_pipeline import (
    run as _run_dataset_pipeline,
    run_from_predictions as _run_predictions_pipeline,
)


@dataclass(frozen=True)
class PipelineConfig:
    """Configuration for the single end-to-end CICIDS2017 SOC pipeline."""

    data_dir: str | None = None
    output_dir: str = "soc_output"
    benchmark_parquet: str | None = None
    verify_only: bool = False
    reuse_predictions: str | None = None
    reasoner: Callable[[dict[str, Any]], str | dict[str, Any]] | None = None


def run_pipeline(config: PipelineConfig) -> None:
    """Run the canonical ingestion-to-investigation workflow.

    The dataset runner owns schema normalization, preprocessing, model fit,
    validation-based calibration and detector scoring. It then passes the
    single alert-flow contract to the SOC orchestrator, which owns event
    correlation, incident formation, graph construction, risk and tool-based
    investigation. No second model or parallel investigation path is started.
    """
    if config.reuse_predictions:
        if config.verify_only or config.benchmark_parquet:
            raise ValueError("--reuse-predictions cannot be combined with benchmark verification options.")
        prediction_path = Path(config.reuse_predictions)
        if not prediction_path.exists() or not prediction_path.is_file():
            raise FileNotFoundError(f"Saved prediction file does not exist: {prediction_path}")
        _run_predictions_pipeline(
            predictions_path=str(prediction_path),
            output_dir=config.output_dir,
            reasoner=config.reasoner,
        )
        return

    if config.verify_only and not config.benchmark_parquet:
        raise ValueError("--verify-only requires --benchmark-parquet.")
    if config.verify_only and not config.data_dir:
        raise ValueError("A data_dir positional argument is still required in verify-only mode.")
    if not config.data_dir:
        raise ValueError("Provide data_dir or use --reuse-predictions.")
    data_path = Path(config.data_dir)
    if not config.verify_only and not data_path.exists():
        raise FileNotFoundError(f"Dataset directory does not exist: {data_path}")
    if not config.verify_only and not data_path.is_dir():
        raise NotADirectoryError(f"Dataset path must be a directory: {data_path}")
    _run_dataset_pipeline(
        data_dir=str(data_path),
        output_dir=config.output_dir,
        benchmark_parquet=config.benchmark_parquet,
        verify_only=config.verify_only,
        reasoner=config.reasoner,
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="End-to-end CICIDS2017 detection, correlation, attack graph and SOC investigation pipeline."
    )
    parser.add_argument(
        "data_dir",
        nargs="?",
        default=None,
        help="Directory containing the eight metadata-rich CICIDS2017 CSV files (omit when replaying saved predictions).",
    )
    parser.add_argument("--output-dir", default="soc_output")
    parser.add_argument(
        "--reuse-predictions",
        default=None,
        help=(
            "Replay behavioural detection and SOC investigation from a saved "
            "cicids_if_predictions_with_metadata.csv without refitting Isolation Forest."
        ),
    )
    parser.add_argument(
        "--benchmark-parquet",
        default=None,
        help="Optional Parquet used only to reproduce the historical notebook benchmark before the SOC run.",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Only run the historical benchmark verifier; requires --benchmark-parquet.",
    )
    args = parser.parse_args(argv)
    run_pipeline(PipelineConfig(
        data_dir=args.data_dir,
        output_dir=args.output_dir,
        benchmark_parquet=args.benchmark_parquet,
        verify_only=args.verify_only,
        reuse_predictions=args.reuse_predictions,
    ))


if __name__ == "__main__":
    main()
