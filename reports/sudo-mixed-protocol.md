# Private real/synthetic/mixed sudo training comparison

This offline experiment tests three normal-training sources under the same
forest parameters and feature schema: synthetic only, real candidates only,
and an approximately 50/50 mixture. No real dataset or real experimental
results are committed to this repository. A private export remains on the Pi.

## Real data and partitions

Input is the existing `sudo-process-candidates-v1` pseudonymized export. Failed
and denied events cannot be normal candidates. Export filtering additionally
excludes successful activity within 15 minutes of an error. Successful commands
remain **provisional** normal candidates, not verified benign actions. The
export's raw-identity and ambiguous-process exclusions remain in effect.

Real partitions are chronological in Europe/Copenhagen:

| Partition | Date range |
|---|---|
| Training | Before 2 November 2026 |
| Calibration/validation | 2 November 2026 |
| Final real test | 3 November 2026 |

A 900-second purge on each side of both boundaries separates rolling features
and the 900-second confirmation history. Features are recomputed separately
inside each partition; test observations do not enter training history. Real
training requires 80 candidate positions; validation and test each require 40.
These counts are correlated process observations, not independent sessions.

All three forests have the same training-row budget, the smaller of available
real training candidates and original synthetic training observations. Sampling
is deterministic without replacement. The mixture uses roughly half of each
source. Matching row count does not match the number of independent behaviors;
the report includes the number of distinct feature vectors and constant columns.

## Fixed model and alert policy

Inputs are the existing first five 300-second features: process, failed,
denied and successful counts, plus failure ratio. There are no clock or raw
identity features in this comparison. Every forest uses 128 trees, random seed
42 and the same maximum sample size. This isolates training source from the
earlier feature-variant search; it is not a comparison against the original
seven-feature, full-size synthetic benchmark.

Raw scores and confirmed flags are reported separately. A confirmation requires
two consecutive anomalous processes in the same pseudonymous group less than
900 seconds apart. A normal-scored process breaks the run. Confirmation is an
additional alert policy, not a property of Isolation Forest itself.

All three variants are reported without automatically choosing a production
winner. Using the final test to choose a variant makes that test development
data for that choice; the selected pipeline then needs another held-out replay.

Each model's threshold is calibrated on the same real validation day and
original synthetic validation scenarios. Selection maximizes synthetic scenario
recall with both provisional-real confirmed-position FPR and synthetic-scenario
FPR at most 5%. Ties prefer fewer real flags, fewer synthetic false positives,
then the higher threshold. No final test decision is used for selection.
Unsupervised fitting uses only normal candidates; labeled synthetic validation
is used for threshold calibration. This should not be described as completely
label-free model selection.

## Evaluation units and limitations

- Real provisional false positives count **process positions**. A confirmation
  may remain true across several positions; this is not a count of emitted
  alerts. The research does not implement production alert cooldowns.
- Other real review events are counted separately; they are not automatically
  true attacks. No real-world attack recall is inferred from unverified logs.
- The known controlled test is matched only if there are three same-group
  failures between 13:15 and 13:20 local time on 3 November. Its result is
  reported as one previously known acceptance probe, never as unseen attack
  coverage. Its samples are not used in fitting or threshold calibration.
- Fresh synthetic evaluation has 500 normal and 400 suspicious scenarios with
  seeds distinct from previous training, validation and historical tests.
  These are new instances of known generator families, not novel attack types.
- Rules, ML plus confirmation, their OR combination and a simple longer-window
  rule are evaluated on the same synthetic cases. This permits checking whether
  ML actually adds detections that simpler rules miss.
- Corrected-double-typo and heavy successful-automation cases are known-family
  challenge checks. They were previously inspected and are not advertised as
  independent unseen benchmarks.
- A short real test period and a small normal calibration sample do not prove
  operational reliability, including when no false positives are observed.

## Running and output

`deploy/sprint5_sudo_mixed_ml_run_pi.sh` takes the full reviewed source SHA and
the existing private export path. It fetches the research branch, extracts
pinned public code and uses the existing venv as vidar. No sudo is needed.
It does not read journald again, deploy a model, restart services, update a
dashboard or send/upload data. Standard output contains aggregate metrics;
private `report.json` and explicitly non-deployable JSON research recipes are
saved under `/home/vidar/yggdrasil-sudo-ml-private`.

The eight new checks cover strict input schema, chronological gaps, causal and
grouped features, equal/reproducible sampling, holdout exclusion from calibration,
separate normal/review metrics and private reproducible output. Tests use only
constructed fixtures, not the user's actual logs.
