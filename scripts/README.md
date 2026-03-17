# Scripts Overview

This folder contains helper scripts used for experiments and diagnostics.

## Recommended entrypoints
- `scripts/benchmark_pruning.py` : pruning latency benchmark.
- `scripts/evaluate_query_expansion.py` : query expansion evaluation and plots.
- `scripts/build_pruning_dataset.py` : build pruning training dataset.

## Deprecated
- `scripts/debug_prune.py`
  - Status: deprecated debug helper.
  - Reason: non-reproducible ad-hoc checks overlap with `benchmark_pruning.py`.
  - Kept for compatibility; may be removed in a future cleanup.
