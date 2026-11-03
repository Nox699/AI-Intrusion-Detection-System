# Prospective controlled sudo probe of frozen models

The mixed full-data baseline is the predeclared primary model. The two other
frozen baseline models are reported as comparisons. No winner is automatically
chosen and no model is activated by this test.

Before generating any probe events, the program hashes the baseline report and
all three model files, checks their thresholds/feature schema/training matrix,
and uses the original loader. That loader reconstructs the forest from saved
normal rows; it does not fit probe observations. File hashes are checked again
after execution. No model file or threshold is rewritten.

The explicitly requested controlled workflow is:

1. Thirty successful `sudo -n /usr/bin/true` invocations as the login user.
2. Three separate service-account sudo processes with one supplied false-password
   line each, targeting only `/usr/bin/true`. An unexpected success or timeout
   stops the remaining attempts; there are no automatic retries.
3. One fixed-end journal snapshot after a short delivery allowance, including at
   least 300 seconds of warm-up. A preflight checks journal access before probes.

The service-account helper has an inner 10-second GNU timeout with a two-second
kill allowance. The outer subprocess and its pipe cleanup also have bounded
waits; a descendant holding a pipe cannot make cleanup wait indefinitely.

The service-account helper prints its PID then execs sudo, preserving that PID.
Labels are matched against trusted journal boot/PID identity, outcomes and the
fixed time interval. Normal PIDs are also checked, not assumed. Missing,
duplicated or incorrectly categorized process identities make the evidence
incomplete. Only the intended 30/3 target processes are scored as labeled probes;
all observed setup, wrapper, warm-up and background processes still participate
in rolling feature history.

The feature history is **not reset** between the successful and failed phases.
The parser's trusted UID is a process credential, not a verified human identity.
If the phases share a group, the failure ratio can be diluted by recent
successful activity. This is explicitly reported as a live mixed-context test,
not falsely presented as a clean isolated three-failure case. The first failure's
actual count, successful count and failure ratio are printed for interpretation.

The predeclared primary controlled criterion is zero raw flags among the 30
known benign target processes and at least one raw flag in the three-process
failure episode. Individual process counts are reported regardless of outcome.
An unsuccessful criterion remains a completed negative experiment; evidence or
execution errors are marked incomplete. Neither outcome triggers retraining.

The exporter's provisional-normal filter is deliberately not used as ground
truth here: it would exclude the benign phase because of nearby later failures.
The controlled labels come from the explicit commands and matched journal
evidence instead. Raw journal, boot IDs, UID/PID and raw stderr are not saved in
the private result. Hashes, versions, thresholds and aggregate counts are saved.

A pass demonstrates one new real benign workflow and one controlled failure
episode through the frozen scoring pipeline. Thirty correlated successes are
not 30 independent workflows. This establishes neither population FPR/recall,
general attack coverage nor value over the sudo rules. Known corrected-typo and
60-process challenge failures remain limitations. The existing shadow sensor
may independently record a rule candidate; this runner sends no notifications.
