# Changelog

Every change to OpenScout is listed here, including detections that were added or removed and false-positive fixes. The app's Changes view reads this same file. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.1.0-alpha.2] - 2026-11-27

Fixes from an independent security review of alpha.1.

### Security
- Release builds refuse every XPC connection unless the caller is signed by OpenScout's team. A build without a team ID refuses all connections.
- A missing or failing scan engine now reads "Not fully protected". A scan with engine errors doesn't count as done, and Downloads files are only logged clean when every engine ran.
- Engines report matches and errors together, so one unreadable file no longer hides detections elsewhere in a batch.
- A crafted file name can no longer redirect a ClamAV finding to a different file, and YARA output that can't be matched to a file counts as an error.
- Files over ClamAV's size limit are reported as not fully scanned instead of passing silently. Limits are raised to 512 MB per file.
- Scans now look inside app bundles. The definitions test against installed apps now scans inside them too.
- If the helper crashes mid-update, the last good definitions set is restored at startup.
- Hung tools are killed after a grace period so they can't freeze the helper.
- The menu stops showing a status once the helper stops answering.
- Quarantine writes its record before moving a file, and never changes permissions through a symlink.
- Quarantining a startup item stops its job first.
- False-positive reports replace your home folder with `~`.
- Pause Scan now pauses until you resume.
- Files that vanish or can't be read mid-scan are listed as skipped, not engine failures, so routine Downloads churn doesn't break protection status.
- File names containing a newline are scanned on their own, so they can't forge results for neighboring files.
- A clean download no longer clears a failed scan's warning.
- The definitions check against installed apps no longer blocks updates because one file couldn't be read, but a definitions set that fails to load is never installed.
- A file in Downloads that can't be read or fully scanned becomes a finding to review instead of passing quietly.
- A stopped scan no longer clears an earlier scan's warning.
- clamscan must pass a version self-test to count as working.
- Quarantining a startup item stops its job only when the loaded job really comes from that file, and never touches OpenScout's own helper.
- freshclam keeps its own folder so it downloads daily diffs, and manual updates respect ClamAV's once-an-hour limit.

## [0.1.0-alpha.1] - 2026-11-27

First tagged pre-beta iteration. The repository stays private until the beta.

### Added
- Startup item watcher: reads LaunchAgents and LaunchDaemons, notices new and changed items within seconds, and checks who signed the program they run.
- Downloads watcher that scans new files once the browser finishes writing them.
- ClamAV and YARA engines, run as separate processes. Every finding records the engine, rule, matched text, file fingerprint and definitions version.
- Quarantine that moves files into an owner-only folder, makes them non-executable, and restores them with their original permissions. It never deletes and never overwrites on restore.
- Allow as a two-step action that covers only the exact bytes allowed. A changed file is checked again.
- Definition updates in five steps: verify, test against installed apps, swap, keep the previous set, record the version. Updates that flag a previously clean app are held.
- Daily quick scan that catches up after sleep. Weekly full scan only with consent, on power, and paused while you use the Mac.
- Checks for Gatekeeper, System Integrity Protection, FileVault and the firewall.
- Menu bar app with five states told apart by shape, a native menu, a findings list with an inspector, Quarantine, Startup Items, Overview and this Changes view.
- First run in three steps: background helper, Full Disk Access, first scan.
- CI on macOS and Linux, and a check that blocks code changes missing from this file.

### Not yet
- Quarantine folder encryption.
- Bundled ClamAV and YARA. Version 0.1 uses copies installed with Homebrew.
- A YARA rule source. No rule set is enabled until its license is confirmed (issue #6).
- Fingerprint lookups against a known-malware service.
- Live blocking and network monitoring, which need Apple's Endpoint Security and Network Extension approval.
- Protection against other software already running as you. See docs/decisions/0002-helper-architecture.md and issue #40.
