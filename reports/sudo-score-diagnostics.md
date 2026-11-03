# Retrospective sudo validation score diagnostics

`deploy/sprint5_sudo_score_diagnostics_pi.sh` reads an existing private dataset,
report and research recipes. It reconstructs the exact frozen forests with the
same normal-training matrices, library version, parameters and random seed.
It verifies matrix fingerprints and reproduces the original calibration before
reporting alternative **validation-only** operating profiles.

No source sampling, model parameters or existing thresholds are changed. No
production configuration is written. The prior final test is not scored again.
The profiles are retrospective descriptions, not newly approved settings.

## A reproducible small-sample budget cliff

The public synthetic-only subset at row budget 181 has training-matrix SHA-256
`02af99371e15ca5c0d8db60e0d7187f51963293c902c613cd2975748c121b5d7`.
On the original 32-normal/32-suspicious validation scenarios:

- Enforcing synthetic scenario FPR at most 5% allows at most one false positive.
  The best feasible threshold detects zero suspicious scenarios.
- A threshold detecting 24 of 32 suspicious scenarios flags two of 32 normal
  scenarios: 6.25% observed FPR, above that declared budget.

This is a diagnosis of a particular frozen subset and alert policy. It does not
establish the score tradeoff for the private real-only or mixed forests; those
are reconstructed and inspected on the Pi. It does not justify automatically
relaxing the FPR budget or claim real-world reliability from 32 normal scenarios.

## Diagnostic output

For each saved model the tool reports the original selected/default thresholds,
the saved operating point, the forest default, and best descriptive profiles
under several real/synthetic validation FPR caps. Raw and confirmation-score
distributions are separated. Private JSON additionally shows feature ranges,
features used for tree splits and exact normal/suspicious feature overlap.
Constant training features cannot produce tree splits; unexpected values in
such a feature do not automatically become a meaningful signal for this forest.

`no_usable_operating_point` means the current calibration has zero suspicious
validation detections. It is not a successful detector just because it generates
no false positives. Nonzero validation detection remains only a research
candidate, never an automatic deployment decision.

The already-inspected real and synthetic final tests become development evidence
for any subsequent changes. An improved pipeline requires another held-out
evaluation; do not relabel repeated tuning on those tests as unseen validation.

The diagnostic runner writes a separate private `diagnostics.json`. It leaves
the original export, report and recipes unchanged. Tests verify frozen matrix
and version checks, the reproducible 5% budget cliff, score distribution bounds,
explicit unusable calibration, validation-only access and preservation of all
original private files.
