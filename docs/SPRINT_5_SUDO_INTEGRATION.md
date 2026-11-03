# Sudo: rule alarms and frozen ML in shadow

Status: implementation and read-only Pi preflight. Nothing in this change
installs, migrates, arms or starts production automatically. The only Pi runner
provided at this stage is `deploy/sprint5_sudo_integration_preflight_pi.sh`.

## Behavior after coordinated deployment

The existing private sudo poll remains the journal parser and rule authority.
Its two rules are `sudo.repeated_auth_failure` and `sudo.permission_denied`.
The bridge imports only candidates at or after an explicitly recorded activation
time, with one redacted evidence row, alarm case and existing outbox entry in
the same production SQLite transaction. Repeated source reads and service
restarts reuse the evidence key. The existing notifier delivers the outbox;
its identity, private delivery database and credential are preserved.

Late candidates are revisited across the retained range; a timestamp watermark
is not used to discard them. Old candidates outside the production retention
period are excluded. A stale, future or regressing source checkpoint holds rule
imports. Invalid candidates roll back the entire destination transaction.
Source reads use the private poll's lock and one read transaction. A crashed
poll can leave validated partial rows; complete journal coverage is not claimed.

The frozen mixed model independently produces a provisional 15-minute snapshot,
with 5 minutes of preceding rolling context and at most 15 visible latest rows.
It uses the original seven-feature `SudoIsolationForest`, default frozen
threshold and raw anomaly decision. Later evidence may revise a process result.
It does not create ML alarm cases or outbox entries. Model failure does not
prevent valid rule imports. Fresh quiet source windows produce zero scored
processes; unreadable or stale sources produce unavailable status.

The saved JSON model reconstructs the forest using its saved normal training
rows. New live observations never enter training or threshold calibration.

Frozen mixed artifact, copied privately during future deployment:

- Version: `sudo-if-15207a3b77b40fe2`
- SHA256: `5839076103232763379a2ae401ee1590b39d22cb28e31ea272fe7ced539bf370`
- Threshold: `0.6616139517267046`
- Source on the evaluated Pi:
  `/home/vidar/yggdrasil-sudo-ml-private/sudo-original-baseline-20261103T200046-156301/mixed_full-model.json`

The worker copy must live under a worker-owned `0700` directory with a
`0400`/`0600` model file. Web receives only the strictly validated anonymous
`sudo-integration.json` snapshot. The model's saved rows and source UID/PID,
boot identities, commands, usernames and journal cursors stay private.

## Deployment dependency

Production schema 5 adds `sudo_evidence`. Collector, web and notifier must all
use compatible source before production is reopened on schema 5. Old schema 4
code rejects schema 5 at startup; its retention code also lacks sudo evidence.
A web-only upgrade is insufficient.

Preflight reports the installed source paths, service accounts, selected
PYTHONPATH/config path, schema and aggregate counts, private source freshness,
and frozen model hash/version. It never prints webhook credentials, complete
unit environments, log records, training vectors or raw config contents. It
does not stop services, migrate, arm, copy a model or send a notification.

After its output is reviewed, deployment needs a versioned root-owned source
snapshot; backups of the production DB and all affected role overrides; a
coordinated service stop/migration/restart; a privately installed frozen model;
an explicit activation time; and a verified integration timer. Preserve the
existing notifier delivery state throughout. Rollback must restore both the
schema-compatible DB backup and the matching role source/overrides together.
The new integration service and timer files are preparation, not activation
instructions.

## Evidence for the exam

Keep the earlier frozen prospective probe result: mixed model flagged 0/30
normal positions and 1/3 failure positions, detecting one controlled episode.
This is one prospective workflow and one episode, not a population FPR/recall
estimate. Corrected typo and heavy successful workload limitations remain.

After actual deployment, capture a new dashboard screenshot showing fresh rule
integration and the frozen ML version in shadow. Then capture one controlled
sudo rule case in the alarm detail view with process count, and separately its
delivery if verified. A registered alarm or outbox row alone does not prove
Discord delivery. Historical synthetic benchmark tables remain explicitly
historical and are not live model performance measurements.

## Development validation

The integration storage/bridge/ML/preflight/web tests pass: 69 tests. The broader
suite passes 831 tests with 14 pre-existing worker-only tests deselected because
this executor runs as root and cannot change UID. Their production root guards
are unchanged. Ruff lint/format, Python compilation, shell syntax and JavaScript
syntax checks pass. Actual installed Pi paths and service compatibility still
require the read-only preflight; no deployment or live delivery is claimed.
