# OpenScout

A free, open-source malware scanner for macOS. It lives in the menu bar, watches the two places Mac malware usually gets in and stays (Downloads and startup items), explains every finding in plain English, and quarantines instead of deleting.

OpenScout is free, with no paid tier, trial, account, ads or telemetry. Every change is in [CHANGELOG.md](CHANGELOG.md), including removed detections and false-positive fixes, and the app's Changes view shows the same list. Detection research runs weekly and lands as issues labeled `research`.

## Status

Current version: 0.1.0-alpha.2 (pre-beta). Every iteration gets a new version, a CHANGELOG.md entry and a git tag. See [docs/decisions/0004-versioning.md](docs/decisions/0004-versioning.md). Version 0.1 is in development. See the open [issues](https://github.com/jaredjordan/openscout-mac/issues) and the milestones v1, v2 and v3. Live blocking waits on Apple's Endpoint Security approval.

## How it's built

| Part | What it does |
| --- | --- |
| `Sources/OpenScoutCore` | Detection logic with no UI: startup items, engines, quarantine, definitions, scheduling. Builds and tests on macOS and Linux. |
| `Sources/OpenScoutMac` | macOS glue: file system events, login item registration, notifications, the XPC contract. |
| `App/OpenScoutHelper` | Background helper launched by launchd. Does all watching, scanning and quarantining. |
| `App/OpenScout` | SwiftUI menu bar app. A window onto the helper, nothing more. |

Architecture decisions are in [docs/decisions](docs/decisions).

## Build

Requirements: macOS 14 or later, Xcode 16 or later, [XcodeGen](https://github.com/yonaskolb/XcodeGen), and for scanning, ClamAV and YARA from Homebrew.

```sh
brew install xcodegen clamav yara
swift test                 # core tests
xcodegen generate          # creates OpenScout.xcodeproj
open OpenScout.xcodeproj
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues go through [SECURITY.md](SECURITY.md), not public issues.

## License

Apache 2.0. ClamAV is GPLv2 and runs as a separate process, never linked. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
