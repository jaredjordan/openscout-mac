import Foundation
import XCTest
@testable import OpenScoutCore

final class PolicyTests: XCTestCase {
    let cal = utcCalendar()
    var settings: ScanSettings = {
        var s = ScanSettings()
        s.fullScanEnabled = true
        return s
    }()
    let away = DeviceConditions(onACPower: true, lowPowerMode: false, userIdleSeconds: 900, screenSharing: false)
    let working = DeviceConditions(onACPower: true, lowPowerMode: false, userIdleSeconds: 5, screenSharing: false)

    func testQuickScanCatchesUpAfterSleep() {
        let now = date("2026-11-27T09:00:00Z")
        XCTAssertTrue(ScanPlanner.quickScanDue(lastQuickScan: nil, now: now, settings: settings, calendar: cal))
        XCTAssertFalse(ScanPlanner.quickScanDue(lastQuickScan: date("2026-11-27T02:05:00Z"), now: now,
                                                settings: settings, calendar: cal))
        XCTAssertTrue(ScanPlanner.quickScanDue(lastQuickScan: date("2026-11-26T02:05:00Z"), now: now,
                                               settings: settings, calendar: cal), "missed 2 a.m. slot runs on wake")
        let beforeSlot = date("2026-11-27T01:00:00Z")
        XCTAssertFalse(ScanPlanner.quickScanDue(lastQuickScan: date("2026-11-26T02:05:00Z"), now: beforeSlot,
                                                settings: settings, calendar: cal))
    }

    func testFullScanNeedsConsentPowerAndIdle() {
        // Sunday 2026-11-29 22:30 UTC, just after the slot.
        let now = date("2026-11-29T22:30:00Z")
        let lastWeek = date("2026-11-22T23:00:00Z")
        XCTAssertTrue(ScanPlanner.fullScanDue(lastFullScan: lastWeek, now: now, settings: settings,
                                              conditions: away, calendar: cal))
        XCTAssertFalse(ScanPlanner.fullScanDue(lastFullScan: lastWeek, now: now, settings: settings,
                                               conditions: working, calendar: cal), "never while the user is active")
        var onBattery = away
        onBattery.onACPower = false
        XCTAssertFalse(ScanPlanner.fullScanDue(lastFullScan: lastWeek, now: now, settings: settings,
                                               conditions: onBattery, calendar: cal))
        var noConsent = settings
        noConsent.fullScanEnabled = false
        XCTAssertFalse(ScanPlanner.fullScanDue(lastFullScan: nil, now: now, settings: noConsent,
                                               conditions: away, calendar: cal), "first run must ask first")
        XCTAssertFalse(ScanPlanner.fullScanDue(lastFullScan: date("2026-11-29T22:10:00Z"), now: now,
                                               settings: settings, conditions: away, calendar: cal))
    }

    func testPauseWhenUserReturns() {
        XCTAssertTrue(ScanPlanner.shouldPauseFullScan(conditions: working))
        XCTAssertFalse(ScanPlanner.shouldPauseFullScan(conditions: away))
    }

    func testLiveActivityIsOptInAndQuiet() {
        var s = ScanSettings()
        XCTAssertFalse(ScanPlanner.showLiveActivity(userStarted: true, settings: s, conditions: working,
                                                    systemSupportsLiveActivities: true), "off by default")
        s.liveActivityEnabled = true
        XCTAssertTrue(ScanPlanner.showLiveActivity(userStarted: true, settings: s, conditions: working,
                                                   systemSupportsLiveActivities: true))
        XCTAssertFalse(ScanPlanner.showLiveActivity(userStarted: false, settings: s, conditions: working,
                                                    systemSupportsLiveActivities: true), "never for scheduled scans")
        var sharing = working
        sharing.screenSharing = true
        XCTAssertFalse(ScanPlanner.showLiveActivity(userStarted: true, settings: s, conditions: sharing,
                                                    systemSupportsLiveActivities: true))
        XCTAssertFalse(ScanPlanner.showLiveActivity(userStarted: true, settings: s, conditions: working,
                                                    systemSupportsLiveActivities: false))
    }

    func testMarkStatePriority() {
        let now = date("2026-11-27T12:00:00Z")
        let fresh = now.addingTimeInterval(-3600)
        func mark(_ fda: Bool?, _ helper: Bool = true, _ findings: Int = 0, _ progress: Double? = nil,
                  _ defs: Date? = nil) -> MarkState {
            ProtectionState.mark(for: ProtectionInputs(fullDiskAccess: fda, helperRunning: helper, openFindings: findings,
                                                       scanProgress: progress, lastDefinitionsUpdate: defs ?? fresh), now: now)
        }
        XCTAssertEqual(mark(false, true, 3, 0.5), .unprotected, "never All clear without Full Disk Access")
        XCTAssertEqual(mark(true, false), .unprotected, "helper down is not protected")
        XCTAssertEqual(mark(true, true, 2, 0.5), .review)
        XCTAssertEqual(mark(true, true, 0, 0.41), .scanning)
        XCTAssertEqual(mark(true, true, 0, nil, now.addingTimeInterval(-5 * 86400)), .stale)
        XCTAssertEqual(mark(true), .clear)
        XCTAssertEqual(mark(nil), .clear, "unknown Full Disk Access isn't a denial")
    }

    func testVoiceOverLabels() {
        let inputs = ProtectionInputs(fullDiskAccess: true, helperRunning: true, openFindings: 1,
                                      scanProgress: 0.41, lastDefinitionsUpdate: nil)
        XCTAssertEqual(ProtectionState.accessibilityLabel(for: .scanning, inputs: inputs), "OpenScout, scanning, 41 percent")
        XCTAssertEqual(ProtectionState.accessibilityLabel(for: .review, inputs: inputs), "OpenScout, 1 finding needs review")
        XCTAssertEqual(ProtectionState.accessibilityLabel(for: .unprotected, inputs: inputs), "OpenScout, not fully protected")
        XCTAssertEqual(Set(MarkState.allCases.map(\.symbolName)).count, 5, "every state has its own symbol")
    }

    func testSeverityOrdering() {
        XCTAssertLessThan(Severity.low, Severity.high)
        XCTAssertEqual(Severity.allCases.max(), .high)
    }
}
