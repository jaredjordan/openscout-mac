import Foundation

/// What the Mac is doing right now. The helper reads these from the system and passes them in,
/// so every scheduling rule is testable.
public struct DeviceConditions: Equatable, Sendable {
    public var onACPower: Bool
    public var lowPowerMode: Bool
    public var userIdleSeconds: TimeInterval
    public var screenSharing: Bool

    public init(onACPower: Bool, lowPowerMode: Bool, userIdleSeconds: TimeInterval, screenSharing: Bool) {
        self.onACPower = onACPower
        self.lowPowerMode = lowPowerMode
        self.userIdleSeconds = userIdleSeconds
        self.screenSharing = screenSharing
    }

    /// The user counts as away after five minutes without input.
    public var userIsIdle: Bool { userIdleSeconds >= 300 }
}

public struct ScanSettings: Codable, Equatable, Sendable {
    public var quickScanHour: Int = 2
    /// Calendar weekday, 1 is Sunday.
    public var fullScanWeekday: Int = 1
    public var fullScanHour: Int = 22
    public var fullScanOnBattery: Bool = false
    /// Off until the user agrees during first run.
    public var fullScanEnabled: Bool = false
    public var liveActivityEnabled: Bool = false

    public init() {}
}

public enum ScanKind: String, Codable, Sendable { case quick, full }

public enum ScanPlanner {
    /// The most recent moment a quick scan was scheduled at or before `now`.
    static func lastQuickSlot(before now: Date, settings: ScanSettings, calendar: Calendar) -> Date? {
        var comps = calendar.dateComponents([.year, .month, .day], from: now)
        comps.hour = settings.quickScanHour
        comps.minute = 0
        guard let today = calendar.date(from: comps) else { return nil }
        return today <= now ? today : calendar.date(byAdding: .day, value: -1, to: today)
    }

    /// Daily quick scan. A missed slot (the Mac was asleep) runs at the next chance.
    public static func quickScanDue(lastQuickScan: Date?, now: Date, settings: ScanSettings,
                                    calendar: Calendar = .current) -> Bool {
        guard let slot = lastQuickSlot(before: now, settings: settings, calendar: calendar) else { return false }
        guard let last = lastQuickScan else { return true }
        return last < slot
    }

    /// Weekly full scan, only on power (unless allowed) and only while the user is away.
    public static func fullScanDue(lastFullScan: Date?, now: Date, settings: ScanSettings,
                                   conditions: DeviceConditions, calendar: Calendar = .current) -> Bool {
        guard settings.fullScanEnabled else { return false }
        guard conditions.onACPower || settings.fullScanOnBattery else { return false }
        guard conditions.userIsIdle, !conditions.lowPowerMode else { return false }
        var comps = DateComponents()
        comps.weekday = settings.fullScanWeekday
        comps.hour = settings.fullScanHour
        comps.minute = 0
        guard let slot = calendar.nextDate(after: now, matching: comps, matchingPolicy: .nextTime,
                                           direction: .backward) else { return false }
        guard let last = lastFullScan else { return true }
        return last < slot
    }

    /// A running full scan pauses the moment the user comes back.
    public static func shouldPauseFullScan(conditions: DeviceConditions) -> Bool {
        !conditions.userIsIdle || conditions.lowPowerMode
    }

    /// The menu bar Live Activity is opt-in and only for scans the user started.
    public static func showLiveActivity(userStarted: Bool, settings: ScanSettings,
                                        conditions: DeviceConditions, systemSupportsLiveActivities: Bool) -> Bool {
        systemSupportsLiveActivities && settings.liveActivityEnabled && userStarted
            && conditions.onACPower && !conditions.lowPowerMode && !conditions.screenSharing
    }
}
