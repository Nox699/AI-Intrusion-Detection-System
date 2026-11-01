# Preauth visibility: Sprint 1 acceptance check

The new **Før login** page displays stored OpenSSH `Connection closed/reset
by authenticating user ... [preauth]` messages separately from authentication
successes and failures. It reads the original `records` table: a schema migration to version 2, no retrospective cursor reset and no new ML features are required.
Existing authentication statistics and alerts remain unchanged.

## Before Pi update

- Keep a valid SQLite backup outside Git, confirmed with
  `PRAGMA integrity_check` = `ok`.
- Wait for passing CI on the feature branch and review the changed files.
- Do not update the running Pi until the change is approved.

## Acceptance test after a controlled update

1. Confirm both services are running and the database reports schema version 2.
2. Open **Før login** and confirm previously observed closed/reset records appear.
3. Verify that `events`, `success`, `failure` and ML observations do not
   increase merely because a preauth record was displayed.
4. Verify the page is unavailable without dashboard authentication.
5. Verify only loopback is listening on port 8765 and the SSH tunnel remains
   the access path.
6. Record the Git commit, before/after counts and whether the observed
   disconnects match the system journal.

**Limitations:** A preauth disconnect cannot alone prove a rejected key or an
attack. Only two SSH log message shapes are displayed; other disconnect
messages and events excluded by journal filtering remain out of scope.
