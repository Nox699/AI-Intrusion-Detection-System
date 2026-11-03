# Restored Sprint 5 full-data baseline

This comparison uses the existing `SudoIsolationForest` class without modifying
its seven-feature schema, 128-tree forest, fixed seed, training-derived default
3% contamination offset or any-raw-anomaly scenario decision. No two-hit policy,
validation-based threshold adjustment, row matching or subsampling is applied.

Three recipes are compared:

- All 681 original synthetic normal observations.
- All available real normal candidates before 3 November, with a 900s purge.
- The full concatenation of those sources.

Different source sizes are reported explicitly. This compares complete practical
recipes, not a controlled causal effect of source alone. Normal real candidates
remain provisional, including the conservative exclusion of error contexts.

Previously inspected 2 November activity now belongs to development training.
This gives the normal baseline access to its previously observed busy activity instead
of repeatedly rejecting it as unseen. 3 November stays out of fitting with a
900s boundary gap and 300s of unscored replay warm-up. Its replay and all previously inspected synthetic scenarios
are descriptive regression/acceptance checks, not new independent holdouts.

The original synthetic recipe must reproduce 15TP/5FP on its validation and
12TP/4FP on its historical test. The tests enforce this result, seven columns,
full matrix sizes, chronological exclusion and original-format model round trips.

Real data uses the exporter's causal process-evidence timestamp. The original
synthetic baseline deliberately keeps its historical fixture timestamp policy.
Thus this restores the original feature formula/model/decision policy, not a
claim that real raw-journal processing is bit-for-bit identical to synthetic
fixtures or ready for streaming deployment. That requires separate acceptance.

Known benign 30/60-process workload and corrected-typo checks remain evaluation
challenges; they are not silently relabeled as new training observations.
Baseline restoration alone is not promised to fix those challenges.

The runner creates a new private directory and original-format JSON model files.
It exercises the original loader/scorer before reporting results. It neither
installs the models nor changes a collector, dashboard, timer or notifier.
The next useful acceptance test must occur after these models are frozen and
must score them without fitting again. Keep that prospective evidence distinct
from this retrospective replay.
