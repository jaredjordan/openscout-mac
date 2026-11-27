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

## Supported versions

Only the latest release.
