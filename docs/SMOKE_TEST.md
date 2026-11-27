# Smoke test on a real Mac

CI compiles everything and runs the core tests, but it can't run the app, the helper or XPC. Run this on a Mac before merging a release. Record the result in the pull request.

Setup:

```sh
brew install xcodegen clamav yara
git checkout feat/v1-foundation
xcodegen generate
open OpenScout.xcodeproj    # build and run the OpenScout scheme (Debug)
```

| # | Check | How | Pass when |
| --- | --- | --- | --- |
| 1 | First run | Launch the app | The setup window opens. Continue registers the helper, and macOS asks to allow it in Login Items |
| 2 | Helper running | `launchctl print gui/$(id -u)/com.jaredjordan.openscout.helper` | State is running |
| 3 | Full Disk Access | Skip it on first run | The menu reads "Not fully protected". Granting it clears that within about 10 seconds |
| 4 | Engine missing | Before ClamAV definitions download | The menu reads "Not fully protected" with the reason, never "All clear" |
| 5 | Definitions | Menu > Update Definitions | Overview shows a definitions version. Calling it again within an hour is refused |
| 6 | Startup item alert | `cp tests/OpenScoutCoreTests/Fixtures/com.update.helper.plist ~/Library/LaunchAgents/` | A finding appears within 10 seconds. The notification shows Quarantine and Review, never Allow |
| 7 | Quarantine | Quarantine that finding | The plist leaves LaunchAgents. Quarantine lists it. The payload in `~/Library/Application Support/OpenScout/Quarantine/<id>/` is mode 0400 |
| 8 | Restore | Restore it from Quarantine | The plist is back with its original permissions and isn't flagged again. Remove it by hand afterward |
| 9 | Download scan | Save the EICAR test file into Downloads | A finding with engine ClamAV and its rule appears |
| 10 | Allow | Allow… on a finding | A confirmation explains the consequence first. Cancel changes nothing |
| 11 | XPC restriction (Release) | Build Release with no OPENSCOUT_TEAM_ID set and run it | The app can't talk to the helper. The menu shows the helper isn't running |
| 12 | XPC restriction (stranger) | Debug build: ad-hoc sign a tiny tool with identifier `com.example.x` and connect to the Mach service | The connection is refused |
| 13 | Definition rollback | Install twice, then call `DefinitionStore.rollback` from a test build, or swap `current`/`previous` and restart the helper | The previous version is back in Overview |
| 14 | Helper dies | `launchctl kill SIGKILL gui/$(id -u)/com.jaredjordan.openscout.helper` | Within about 10 seconds the menu stops showing "All clear" |
