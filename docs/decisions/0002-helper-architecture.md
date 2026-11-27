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

## Threat model limit (from the security review)

The helper runs as the user. Anything else running as that same user can already read and write the helper's files in `~/Library/Application Support/OpenScout`: the allow list, state, quarantine records and definitions. It can also replace a Homebrew-installed `clamscan`, because on Intel Macs `/usr/local/bin` is writable by the user. Malware that already runs as you can therefore blind OpenScout without touching XPC.

Version 1 accepts this limit, as most user-level scanners do, and does three things about it:

- Release builds refuse XPC connections unless the caller is signed by OpenScout's team. A build with no team ID refuses everything.
- An engine that's missing or failing makes the mark read "Not fully protected", never All clear.
- The limit is written down here, and tracked as an issue: sign the allow list and quarantine records with a key only the helper can read, and ship ClamAV and YARA inside the signed app so they can't be swapped.

A root-owned component (a privileged helper or an Endpoint Security system extension) is the real fix. That arrives with version 3.
