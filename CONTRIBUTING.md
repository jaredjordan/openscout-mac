# Contributing

Thanks for helping. A few rules keep OpenScout trustworthy.

1. Every code change has a CHANGELOG.md entry in the same pull request, written for people. CI blocks it otherwise.
2. Core logic goes in `Sources/OpenScoutCore` with tests in `tests/OpenScoutCoreTests`. Run `swift test` before opening a pull request.
3. Use conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`) and reference the issue.
4. Never delete user files. Never run a tool through a shell. Never report an engine failure as clean.

## Detection rules

YARA rules must come with:

- a source and a license compatible with Apache 2.0, listed in THIRD_PARTY_NOTICES.md
- at least one sample hash it should match, and a note on what it must not match
- a CHANGELOG.md line under Added, or under Removed when a rule goes

## False positives

Use Report False Positive in the app. It opens an issue with the rule, engine, fingerprint and definitions version already filled in.
