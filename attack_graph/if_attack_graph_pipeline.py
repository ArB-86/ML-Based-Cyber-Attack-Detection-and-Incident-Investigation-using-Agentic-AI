"""Backward-compatible entry point for the canonical SOC pipeline.

Historically this module contained a separate prototype detector/event/graph
implementation. That parallel path is retired: all commands now delegate to
attack_graph.pipeline so detection, correlation, graphing and investigation
share one incident lifecycle and output contract.
"""
from __future__ import annotations

from .pipeline import PipelineConfig, main, run_pipeline


def run(
    data_dir: str,
    output_dir: str = "soc_output",
    **kwargs,
) -> None:
    """Compatibility wrapper; use attack_graph.pipeline as the main entry."""
    allowed = {"benchmark_parquet", "verify_only"}
    unknown = set(kwargs) - allowed
    if unknown:
        raise TypeError(
            "Prototype-only options have been retired. "
            f"Unsupported options: {sorted(unknown)}. "
            "Use the canonical pipeline configuration instead."
        )
    run_pipeline(PipelineConfig(
        data_dir=data_dir,
        output_dir=output_dir,
        benchmark_parquet=kwargs.get("benchmark_parquet"),
        verify_only=bool(kwargs.get("verify_only", False)),
    ))


if __name__ == "__main__":
    main()
