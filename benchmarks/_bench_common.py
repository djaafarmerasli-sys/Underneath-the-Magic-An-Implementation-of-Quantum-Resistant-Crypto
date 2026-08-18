"""
_bench_common.py -- shared measurement/reporting helpers for benchmarks/
================================================================================

Not a benchmark itself -- a small internal utility module the four
benchmark_*.py scripts share, so the methodology (warm-up, repetitions,
statistics, environment metadata, JSON export) is identical across all of
them and only needs to be gotten right once.

METHODOLOGY
-------------
* Warm-up: every timed operation runs a few untimed iterations first, so
  one-time costs (import machinery, CPU frequency scaling, disk/page
  caching) don't bias the first measured sample.
* Repetition: each operation is repeated many times; we report mean,
  median, and standard deviation, not a single sample.
* Independence: each repetition is a fresh operation on fresh input where
  that matters (e.g. a fresh keypair per encapsulation sample) -- see each
  benchmark_*.py file for exactly what is/isn't held fixed across samples,
  since reusing state across "independent" measurements would make the
  comparison misleading.
* No hard-coded expectations: this module only measures and reports: it
  contains no assertions about what a "good" or "expected" timing is.

These results are inherently hardware- and software-version-dependent (see
`environment_metadata()` below) -- they describe THIS run, on THIS machine,
with THESE installed library versions, nothing more universal than that.
"""

from __future__ import annotations

import json
import platform
import statistics
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

RESULTS_DIR = Path(__file__).resolve().parent.parent / "data" / "benchmark_results"

# How many untimed iterations to run before timing begins.
DEFAULT_WARMUP_ITERATIONS = 3


@dataclass(frozen=True)
class TimingStats:
    """Summary statistics for one benchmarked operation, over `iterations`
    independently-timed repetitions."""

    operation: str
    iterations: int
    mean_seconds: float
    median_seconds: float
    stdev_seconds: float
    min_seconds: float
    max_seconds: float
    ops_per_second: float
    extra: dict[str, Any] = field(default_factory=dict)


def time_operation(
    operation: str,
    func: Callable[[], Any],
    *,
    iterations: int,
    warmup_iterations: int = DEFAULT_WARMUP_ITERATIONS,
    extra: dict[str, Any] | None = None,
) -> TimingStats:
    """Time `func` (called with no arguments) `iterations` times, after
    `warmup_iterations` untimed warm-up calls.

    `func` is responsible for doing whatever independent setup its own
    measurement validity requires (e.g. generating a fresh keypair before
    timing an encapsulation) -- this helper only handles the clock.
    """
    for _ in range(warmup_iterations):
        func()

    samples: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        func()
        samples.append(time.perf_counter() - start)

    mean = statistics.mean(samples)
    return TimingStats(
        operation=operation,
        iterations=iterations,
        mean_seconds=mean,
        median_seconds=statistics.median(samples),
        stdev_seconds=statistics.stdev(samples) if len(samples) > 1 else 0.0,
        min_seconds=min(samples),
        max_seconds=max(samples),
        ops_per_second=(1.0 / mean) if mean > 0 else float("inf"),
        extra=extra or {},
    )


def environment_metadata() -> dict[str, Any]:
    """Non-secret, reproducibility-relevant facts about the machine and
    software running this benchmark. No file paths, usernames, or other
    machine-identifying details beyond what `platform` reports about the
    OS/CPU/Python build."""
    metadata: dict[str, Any] = {
        "python_version": sys.version,
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "machine": platform.machine(),
    }
    for package_name in ("cryptography", "kyber_py", "dilithium_py"):
        try:
            module = __import__(package_name)
            metadata[f"{package_name}_version"] = getattr(module, "__version__", "unknown")
        except ImportError:
            metadata[f"{package_name}_version"] = None
    return metadata


def write_results(benchmark_name: str, results: list[TimingStats]) -> Path:
    """Write `results` (plus environment metadata and a timestamp) as JSON
    under data/benchmark_results/, and return the path written.

    The output is machine-readable (a single JSON object) so it can be
    diffed across runs or fed into a plotting script without re-parsing
    console output.
    """
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "benchmark": benchmark_name,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "environment": environment_metadata(),
        "results": [asdict(result) for result in results],
    }
    output_path = RESULTS_DIR / f"{benchmark_name}.json"
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return output_path


def print_table(results: list[TimingStats]) -> None:
    """Human-readable console summary, printed alongside the JSON export."""
    header = f"{'operation':<28} {'iters':>6} {'mean':>12} {'median':>12} {'stdev':>12} {'ops/sec':>12}"
    print(header)
    print("-" * len(header))
    for result in results:
        print(
            f"{result.operation:<28} {result.iterations:>6} "
            f"{_fmt(result.mean_seconds):>12} {_fmt(result.median_seconds):>12} "
            f"{_fmt(result.stdev_seconds):>12} {result.ops_per_second:>12.1f}"
        )


def _fmt(seconds: float) -> str:
    if seconds < 1e-3:
        return f"{seconds * 1e6:.1f}us"
    if seconds < 1:
        return f"{seconds * 1e3:.2f}ms"
    return f"{seconds:.3f}s"
