# Sudo: rule alarms and frozen ML in shadow

Status: implementation and coordinated Pi deployment runner. The read-only
preflight was run on Yggdrasil and confirmed all three production roles use
schema4 with no source overrides; the private source checkpoint was fresh and
the frozen 1100-row mixed model hash/version matched. Activation still requires
running the pinned `deploy/sprint5_sudo_integration_install_pi.sh` on the Pi.

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

Frozen mixed artifact, copied privately during deployment:

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

The installer rechecks these runtime assumptions, stages a root-owned source
overlay for all three roles, copies the frozen model into worker-private state,
and validates configuration, existing SSH model loading, sudo model identity
and web privacy as the actual service accounts before stopping production.
It then stops the roles together, makes a root-private SQLite backup, adds
coordinated source overrides, migrates to schema5 as the worker, and verifies
fingerprints of every pre-existing table including the outbox and its identity.
The existing venv, configuration and notifier delivery database are preserved.
There is no pip install, credential rotation or notifier bootstrap.

After role access, service health and the login page are verified, the installer
records the activation boundary and runs the integration service once. It
checks the anonymous snapshot as the web account, then enables the new minute
timer. The updated dashboard is served on production port **8765**. A previously
started manual preview on 8766 uses its old source and is separate. The installer
does not generate controlled sudo failures or test notifications.

Initial acceptance verifies the export as the actual web account: both rule
and ML status must be ready, use the expected activation boundary and frozen
model version, and share a generation time at or after the current start call.
A zero start exit status alone cannot pass because a failed systemd condition
may skip execution; an older otherwise healthy export cannot pass either.

The first Pi attempt completed four integration runs with active rules, zero
new cases and ML in shadow, as recorded in its journal. The installer then
incorrectly rejected the run and completed recovery to schema4. Its acceptance
gate depended on `Result`/`ConditionResult` after an inactive oneshot finished.
Those execution properties were not captured, so their exact observed values
are unknown. The [systemd unit documentation](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html#Unit%20Garbage%20Collection)
documents that unreferenced inactive units can lose their runtime state after
collection. Acceptance now depends on the durable current export rather than
those disposable properties. Regression tests use an inactive completed
service with `ConditionResult=no`, and separately test skipped/failed starts.

Automatic recovery stops the integration and production roles together. When
no sudo alarm evidence exists, it removes the schema5-only empty table and
activation state, returns all roles to their original installed source, and
restarts them. It preserves current SSH/UFW records and outbox contents, including
activity added after the upgrade; it does **not** restore a stale DB image over
live history or replace notifier delivery state. The offline backup remains
available for separate disaster recovery.

If a genuine sudo alarm was already committed, automatic recovery disables the
integration while retaining the compatible schema5 source and its evidence.
Manual rollback likewise refuses to discard new sudo evidence and requires a
forward repair. With no sudo evidence and unchanged integration overrides, use
the same pinned runner with a second argument `rollback`:

```bash
bash <(git show "$sha:deploy/sprint5_sudo_integration_install_pi.sh") "$sha" rollback
```

The runner refuses existing integration paths/backups instead of overwriting
an earlier installation. The normal installation needs a brief coordinated
restart of collector, web and notifier; the private sudo poll/export timers
continue independently.

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

The integration storage/bridge/ML/preflight/web tests pass, with additional
deployment tests covering a successful coordinated release, new SSH activity
during failed activation, preservation of current outbox/delivery history,
private umask permissions, pre-start validation failure and refusal to discard
sudo evidence. The executor runs as root and cannot change UID; the 14
pre-existing worker-only tests are excluded from its broad run. Their production
root guards are unchanged. Ruff lint/format, Python compilation, shell syntax
and JavaScript syntax checks are required. Actual Pi installation and live
delivery are verified separately; preparation is not deployment evidence.

The deployment revision passed 839 tests with those 14 root-incompatible tests
deselected. The complete workflow lint/format commands and new shell/Python
syntax checks passed. Production service execution remains a Pi acceptance
step, rather than something simulated tests can establish.

The current-run acceptance fix passed 846 tests with the same 14 exclusions;
workflow lint/format and the installer syntax checks also passed.
