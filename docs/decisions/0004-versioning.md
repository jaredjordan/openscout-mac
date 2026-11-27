# 0004: Versioning and pre-beta visibility

Status: accepted, 2026-11-27

## Decision

OpenScout uses semantic versioning. Every iteration that ships gets a new version, a CHANGELOG.md release entry and a git tag.

- Before beta, versions are `0.1.0-alpha.N`. N goes up by one each iteration. The first is `0.1.0-alpha.1`.
- `VERSION` at the repo root holds the full version. It's the one place scripts and agents read.
- `MARKETING_VERSION` in `project.yml` holds only the numeric part (`0.1.0`), because Apple requires `CFBundleShortVersionString` to be three integers. `CURRENT_PROJECT_VERSION` goes up by one each iteration, so every build is distinct.
- CHANGELOG.md moves the notes under `[Unreleased]` into a dated `## [version] - YYYY-MM-DD` heading. The app's Changes view reads that same file.
- The tag is `v<version>`, made on the default branch after the change merges.
- The beta starts at `0.1.0-beta.1`. The repository stays private until then.
