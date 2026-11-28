# Security policy

OpenScout runs a background helper that can move files, so a bug in it matters more than most.

## Reporting a vulnerability

Don't open a public issue. Use GitHub's private vulnerability reporting on this repository (Security tab > Report a vulnerability). Include what an attacker can do, what they need, steps to reproduce, and the OpenScout and macOS versions.

You'll get an acknowledgement within 72 hours. Fixes ship in the next weekly release, or sooner for anything that lets another process control the helper. Every security fix is listed in CHANGELOG.md once it ships.

## In scope

- The helper's XPC interface and anything that lets another process drive it
- Quarantine and restore paths, including symlink and race tricks
- The definition updater: anything that installs unverified data
- Parsing of property lists and engine output
- Anything that sends file data off the Mac

## Out of scope for 0.1

Software already running under your own account can modify OpenScout's files in `~/Library/Application Support/OpenScout` or replace the Homebrew-installed scan engines. Reports of that class are known and tracked in #40, and won't be treated as new vulnerabilities until a root-owned component ships. The project owner accepted this for 0.1 on 2026-11-27. Bypasses that need no prior code execution as you are in scope.

## Supported versions

Only the latest release.
