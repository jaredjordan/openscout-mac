import Foundation

/// The five states of the menu bar mark. Each has its own shape so it reads without color.
public enum MarkState: String, Codable, CaseIterable, Sendable {
    case clear, scanning, review, stale, unprotected

    /// SF Symbol names used by the app. Template images, so the system tints them.
    public var symbolName: String {
        switch self {
        case .clear: return "shield"
        case .scanning: return "shield.lefthalf.filled"
        case .review: return "exclamationmark.shield"
        case .stale: return "clock.arrow.circlepath"
        case .unprotected: return "shield.slash"
        }
    }

    public var headline: String {
        switch self {
        case .clear: return "All clear"
        case .scanning: return "Scanning"
        case .review: return "Needs review"
        case .stale: return "Definitions are out of date"
        case .unprotected: return "Not fully protected"
        }
    }
}

public struct ProtectionInputs: Equatable, Sendable {
    public var fullDiskAccess: Bool?
    public var helperRunning: Bool
    public var openFindings: Int
    public var scanProgress: Double?
    public var lastDefinitionsUpdate: Date?

    public init(fullDiskAccess: Bool?, helperRunning: Bool, openFindings: Int,
                scanProgress: Double?, lastDefinitionsUpdate: Date?) {
        self.fullDiskAccess = fullDiskAccess
        self.helperRunning = helperRunning
        self.openFindings = openFindings
        self.scanProgress = scanProgress
        self.lastDefinitionsUpdate = lastDefinitionsUpdate
    }
}

public enum ProtectionState {
    /// Priority: a scanner that can't see everything must never say All clear.
    public static func mark(for inputs: ProtectionInputs, now: Date) -> MarkState {
        if inputs.fullDiskAccess == false || !inputs.helperRunning { return .unprotected }
        if inputs.openFindings > 0 { return .review }
        if inputs.scanProgress != nil { return .scanning }
        if UpdatePolicy.isStale(lastUpdate: inputs.lastDefinitionsUpdate, now: now) { return .stale }
        return .clear
    }

    /// What VoiceOver reads for the menu bar item.
    public static func accessibilityLabel(for state: MarkState, inputs: ProtectionInputs) -> String {
        switch state {
        case .scanning:
            if let p = inputs.scanProgress {
                return "OpenScout, scanning, \(Int((p * 100).rounded())) percent"
            }
            return "OpenScout, scanning"
        case .review:
            let n = inputs.openFindings
            return "OpenScout, \(n) \(n == 1 ? "finding needs" : "findings need") review"
        default:
            return "OpenScout, \(state.headline.lowercased())"
        }
    }
}
