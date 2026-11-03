# Navigation warnings for unseen alert revisions

The menu triangle indicates new or updated registered alarm cases from the
last 24 hours that have not been seen in this browser. It is not a counter of
raw events, private sudo candidates or provisional ML scores.

Opening a section acknowledges its current cases. Opening an alarm detail
acknowledges only that case; opening the alarm overview acknowledges the current
24-hour cases across sections. Acknowledging a sudo case clears both its Sudo
triangle and its contribution to the shared Alarmer triangle. Other unseen
cases keep their own warnings. A new case or a higher finding count on an
existing case shows the warning again, including updates to older case IDs.

Seen state is local browser state keyed by the existing alarm database instance.
There is no production schema migration, server acknowledgement write, deletion
of alarms, notifier reset or effect on Discord delivery. Another browser/origin
has independent seen marks. Private mode or cleared browser storage can reset
them. The stored fields are anonymous alarm IDs, count/revision timestamps and
the mark time, never event text, addresses, usernames or credentials.

The server captures a bounded revision snapshot before rendering the page's
data. JavaScript acknowledges that initial snapshot once. Subsequent polls on
an already open page only show new arrivals; they never silently acknowledge
them. Invalid/error pages do not acknowledge a section. Failed API requests keep
existing warnings; old page snapshots cannot overwrite newer seen revisions.
Cross-tab storage events update the marker, and navigation from the browser's
back/forward cache resumes polling. Seen entries expire after 48 hours and are
bounded to 10,000; recent-case exports reject overflow rather than return a
truncated snapshot as if it were complete.

The previous menu implementation indicated any registered case in the last
24 hours and therefore intentionally stayed visible after a click. This change
implements the requested seen/unseen interaction while preserving alarm history.

## Pi web-only release

Run pinned `deploy/sprint5_nav_unread_web_pi.sh` as vidar. It requires the
verified schema5 integration release `9ced7d60ab7b6776af95a12e83596683e04676ae`.
It stages a separate root-owned web source at `/opt/yggdrasil-nav-unread-web`,
validates readonly data and authenticated routes as `yggdrasil-web`, and adds
only `70-nav-unread.conf` to the existing web service. Collector, notifier,
private sudo timers, model files and configuration are unchanged. Only web is
restarted. Refresh port 8765 with Ctrl+F5 to load the new client code.

The previous source override is retained and backed up privately. A failed
release removes the new override and restarts the previous web source. For an
explicit later rollback, run the same pinned wrapper with a second argument
`rollback`; it verifies the installed release/override before removing it.
Neither path restores an older production database or changes delivery history.

Verification covers clearing matching section/global markers, independent
sections and detail views, new cases and old-case updates, stale snapshots,
browser persistence, failed polls and API privacy/readonly behavior. The Node
tests use only its standard test runner, with no npm dependencies. A final
browser acceptance check should open Sudo, verify the triangle clears, then
observe its return on a subsequent new or updated registered alarm.

Validation: 865 Python tests passed with the 14 existing root-incompatible
worker tests deselected, and all 9 Node interaction tests passed. Workflow
lint/format, JavaScript/shell syntax and both inline Python blocks passed.
Pi activation remains a separate web-only acceptance step.
