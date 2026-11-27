# CLAUDE.md

OpenScout: free, open-source macOS malware scanner. Read README.md, then docs/decisions/.

Rules for agents working in this repo:

- Every code change gets a CHANGELOG.md entry in the same pull request. CI enforces it. Removed detections and false-positive fixes are listed too.
- Never delete user files. Quarantine moves, restore never overwrites.
- External tools run through `CommandRunner` with an argument array and `--` before paths. Never through a shell.
- Every finding carries full evidence: path, SHA-256, engine, rule ID, match, definitions version, signer.
- An engine failure is never reported as clean.
- Full Disk Access unknown is not denied, but denied always shows "Not fully protected".
- Core logic goes in `Sources/OpenScoutCore` with tests in `tests/`. It must build on Linux.
- ClamAV (GPLv2) is never linked. It runs as a separate process.
- Conventional commits. Reference the GitHub issue in the commit body.
- No secrets in the repo. Signing identities stay in the keychain and CI secrets.
- UI copy: plain English, no jargon. Allow is always a two-step action.

Wakanda: `wakanda/contract.json` is a draft `macos-app` profile. The harness isn't installed in this repo yet. Don't claim Wakanda gates ran here.
