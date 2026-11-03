# Sudo Isolation Forest research, 3 November 2026

The experimental candidate improves synthetic detection and reduces false
positives relative to the original sudo IF. It is not ready for live alerts:
all 50 benign successful-automation stress scenarios were flagged. A simple
longer-window rule matches the hybrid's detection on this generator with fewer
false positives. There is no demonstrated unique ML advantage over that rule.

## Reproducible comparison

The full method and aggregate/per-type results are in
`sudo-if-v2-summary.json`. Run `deploy/sprint5_sudo_ml_v2_run_pi.sh` with the
full experiment commit SHA to reproduce the private full report on Yggdrasil.
The runner extracts pinned sources into a temporary directory and uses the
existing Python environment. It does not install or activate a model.

All figures count **scenarios**, not log lines, sudo processes or verified
attacks. The fresh-seed holdout contains 400 labeled suspicious scenarios and
500 normal scenarios from the **same original synthetic generator**.

| Detector | Suspicious detected | Benign flagged |
|---|---:|---:|
| Original IF, original threshold | 204/400 (51%) | 69/500 (13.8%) |
| Candidate IF with calibrated threshold and confirmation | 300/400 (75%) | 21/500 (4.2%) |
| Original sudo rules | 300/400 (75%) | 0/500 |
| Original rules OR candidate | 400/400 | 21/500 (4.2%) |
| Simple longer-window rule | 400/400 | 0/500 |

The benign stress holdout is reported separately, not hidden inside a more
favorable aggregate:

| Benign stress family | Original IF flagged | Candidate flagged | Longer-window rule flagged |
|---|---:|---:|---:|
| Two typos, each followed by a successful correction | 29/50 | 0/50 | 0/50 |
| Thirty successful sudo processes, two seconds apart | 50/50 | 50/50 | 0/50 |

Zero observed false positives for a rule is not a claim of zero operational FPR.
Two failures seven minutes apart are labeled suspicious by this laboratory;
that label alone does not establish malicious intent on a real server.

## What changed

The selected candidate uses five 300-second process-count/ratio features and
omits clock features. A validation-calibrated threshold must be exceeded by two
**consecutive** process observations in the same boot/UID group within 900
seconds. A normal-scored observation between them breaks confirmation. The
second process is the earliest possible confirmation, so this changes alert
latency as well as false positives.

This is an improved **IF plus alert policy**, not evidence that the raw forest
alone became better. Training remains unsupervised and normal-only; threshold
selection uses labeled development validation. Clock removal is justified only
for this experiment, whose synthetic start times are randomized; real usage may
have a meaningful time-of-day pattern.

The fair non-ML comparator triggers on sudoers denial or two consecutive failed
processes within 900 seconds, with a successful process breaking the run.

## Evaluation boundaries

- Original 180 normal training scenarios are unchanged.
- Original validation data selects among four feature representations, one/two
  consecutive observations, and score-breakpoint thresholds, with at most 5%
  validation FPR. Exploratory sampling/feature/confirmation checks preceded
  this experiment; these development results are not independent validation.
- Original 32+32 test scenarios had already been inspected. They are explicitly
  marked descriptive/development only and are not used for candidate selection.
- Selection completes before either fresh holdout is constructed or scored.
  Training, validation, historical test, fresh test and stress seeds are disjoint.
- Fresh results and stress outcomes were not used to revise this candidate.
  Reproducible reruns and unit tests do not create additional unseen tests.
- Every process feature uses only current/past events. Multiple PAM/summary
  lines remain one process. Groups remain separate by boot and UID.
- The experiment accesses no real journal, production database, secrets or
  network service. It changes no collectors, timers, exporters, dashboards or
  Discord settings. The saved JSON is a non-deployable research recipe.

## Interpretation and next evidence

The original IF already adds coverage: it found 4 slow-failure scenarios missed
by the original rules in the historical 32+32 test. Historical OR coverage was
28/32 with 4 false positives, rather than merely duplicating all rule detections.

The candidate preserves useful slow-failure coverage while suppressing isolated
typos more successfully, but normal automation is outside its training workload.
Representative labeled normal maintenance/automation activity and a separately
held-out real sudo replay are needed before recommending live ML alarms.
Further tuning must treat the now-inspected fresh/stress cases as development
data and use another held-out evaluation. Do not deploy this recipe as the
existing `sudo-isolation-forest-v1` model or overwrite the dashboard benchmark.

## Local validation

The seven new research tests and four real-export tests pass, including causal features, process grouping,
confirmation boundaries, split independence, holdout exclusion during selection,
and private output. The targeted sudo rules/storage/ML suite passes 63 tests;
one original test requiring an unprivileged process is excluded in that run.
Lint, formatting, Python compilation, shell syntax and whitespace checks pass.

At the first research checkpoint, the complete suite reported 731 passed and 14 failed in this root-only executor.
All 14 failures reach existing unprivileged-user checks in unchanged sudo lab
and poll modules; they cannot run as root. An attempted unprivileged invocation
is unsupported by this executor's UID mapping. Full non-root CI/Pi validation
remains outstanding. No root check was weakened to obtain a passing result.

## Running the real-data inventory from Git

The separate research branch also provides
`deploy/sprint5_sudo_real_export_pi.sh`. Run it as vidar with the pinned full
commit SHA. It extracts the exact public parser and exporter from Git, runs a
read-only journal query as the existing worker with primary group
`yggdrasil-data` and supplementary `systemd-journal`, and saves a fresh private
JSON export in `/home/vidar/yggdrasil-sudo-real-private`. Standard output shows
only aggregate counts and the private dataset path.

The dataset retains timestamps, coarse outcomes and export-local group numbers.
Raw messages, commands, user names, UID/PID, boot IDs and journal cursors are
not exported. Failed/denied processes and successful activity within 15 minutes
of a failure remain excluded from provisional normal candidates. Ambiguous
process groups spanning more than 15 minutes are omitted and counted. Normal
labels are not verified by this filtering. The source contains no user logs,
and the runner does not upload the dataset to GitHub or change services.
