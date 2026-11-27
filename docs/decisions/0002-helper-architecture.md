# 2. A background helper does the work, the app only shows it

Date: 2026-11-27. Status: accepted.

## Context

Protection has to keep running when the window is closed or the app crashes. Real-time blocking needs Apple's Endpoint Security entitlement, which can take months or more to get.

## Decision

- `OpenScoutHelper` is a launch agent registered with `SMAppService`. It runs as the user, watches startup item folders and Downloads with FSEvents (no entitlement needed), runs scheduled scans, quarantines and updates definitions.
- The menu bar app talks to it over XPC (`com.jaredjordan.openscout.helper`). The helper treats the app as a client: every argument is validated, and a connection must pass a code signing requirement. Signed builds require the team ID.
- Allow is accepted over XPC only with `confirmed: true`, which the app sends only after its confirmation dialog.

## Consequences

Version 1 detects within seconds but can't block a process before it runs. That waits for Endpoint Security (issue for F11). Development builds check only the bundle identifier, which is weaker, so release builds must set `OPENSCOUT_TEAM_ID`.
