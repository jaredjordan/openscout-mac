# 3. Deployment target macOS 14, designed for macOS 27

Date: 2026-11-27. Status: accepted, revisit when CI has a macOS 26 runner with Xcode 26.

## Context

The spec targets the Golden Gate design language and names macOS 26 as the minimum. The app uses `MenuBarExtra`, `.inspector`, `ContentUnavailableView` and `SettingsLink`, which need macOS 14. Liquid Glass APIs need the macOS 26 SDK, which the current CI runner image may not have.

## Decision

Set the deployment target to macOS 14. System controls pick up Liquid Glass automatically when built with the newer SDK. Custom glass effects and the 27.3 Live Activity go behind availability checks when they're added.

## Consequences

More Macs can run OpenScout. The cost is that glass-specific code needs compile-time and runtime guards.
