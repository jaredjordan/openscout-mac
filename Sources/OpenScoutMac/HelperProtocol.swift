import Foundation
import OpenScoutCore

/// Mach service the helper listens on. Declared in the helper's launchd plist.
public enum HelperIdentity {
    public static let machServiceName = "com.jaredjordan.openscout.helper"
    public static let launchAgentPlistName = "com.jaredjordan.openscout.helper.plist"
}

/// Snapshot the app shows. Sent over XPC as JSON so both sides share one Codable model.
public struct HelperStatus: Codable, Equatable, Sendable {
    public var mark: MarkState
    public var accessibilityLabel: String
    public var fullDiskAccess: Bool?
    public var lastQuickScan: Date?
    public var lastFullScan: Date?
    public var lastDefinitionsUpdate: Date?
    public var definitionsVersion: String?
    public var scanProgress: Double?
    public var scanPaused: Bool
    public var findings: [Finding]
    public var startupItems: [StartupItem]
    public var posture: [PostureResult]
    public var recentActivity: [ActivityEntry]
    public var settings: ScanSettings
    /// Why protection is incomplete, in plain words. Empty when everything ran.
    /// Optional so an older helper's reply still decodes.
    public var problems: [String]?

    public init(mark: MarkState, accessibilityLabel: String, fullDiskAccess: Bool?, lastQuickScan: Date?,
                lastFullScan: Date?, lastDefinitionsUpdate: Date?, definitionsVersion: String?,
                scanProgress: Double?, scanPaused: Bool, findings: [Finding], startupItems: [StartupItem],
                posture: [PostureResult], recentActivity: [ActivityEntry], settings: ScanSettings,
                problems: [String]?) {
        self.mark = mark
        self.accessibilityLabel = accessibilityLabel
        self.fullDiskAccess = fullDiskAccess
        self.lastQuickScan = lastQuickScan
        self.lastFullScan = lastFullScan
        self.lastDefinitionsUpdate = lastDefinitionsUpdate
        self.definitionsVersion = definitionsVersion
        self.scanProgress = scanProgress
        self.scanPaused = scanPaused
        self.findings = findings
        self.startupItems = startupItems
        self.posture = posture
        self.recentActivity = recentActivity
        self.settings = settings
        self.problems = problems
    }
}

public struct ActivityEntry: Codable, Equatable, Identifiable, Sendable {
    public var id: UUID
    public var date: Date
    public var text: String

    public init(id: UUID = UUID(), date: Date = Date(), text: String) {
        self.id = id
        self.date = date
        self.text = text
    }
}

#if os(macOS)
/// The XPC surface between the menu bar app and the background helper.
/// Every reply carries JSON or an error string. The helper validates every argument:
/// the app is a client, not a trusted caller.
@objc public protocol OpenScoutHelperProtocol {
    func status(reply: @escaping (Data?, String?) -> Void)
    func startScan(kind: String, reply: @escaping (String?) -> Void)
    func pauseScan(reply: @escaping (String?) -> Void)
    func resumeScan(reply: @escaping (String?) -> Void)
    func stopScan(reply: @escaping (String?) -> Void)
    func quarantine(findingID: String, reply: @escaping (String?) -> Void)
    /// Second step of Allow. The app must have shown the consequence and been confirmed.
    func allow(findingID: String, confirmed: Bool, reply: @escaping (String?) -> Void)
    func quarantineRecords(reply: @escaping (Data?, String?) -> Void)
    func restore(recordID: String, reply: @escaping (String?) -> Void)
    func updateDefinitions(reply: @escaping (String?) -> Void)
    /// JSON-encoded ScanSettings.
    func updateSettings(_ data: Data, reply: @escaping (String?) -> Void)
}

public extension NSXPCInterface {
    static var openScoutHelper: NSXPCInterface {
        NSXPCInterface(with: OpenScoutHelperProtocol.self)
    }
}
#endif
