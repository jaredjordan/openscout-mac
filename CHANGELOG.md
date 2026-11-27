# Changelog

Every change to OpenScout is listed here, including detections that were added or removed and false-positive fixes. The app's Changes view reads this same file. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
