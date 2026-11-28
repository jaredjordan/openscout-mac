import Foundation

/// How serious a finding is. Ordered from least to most serious.
public enum Severity: String, Codable, Comparable, CaseIterable, Sendable {
    case info, low, medium, high

    private var rank: Int {
        switch self {
        case .info: return 0
        case .low: return 1
        case .medium: return 2
        case .high: return 3
        }
    }

    public static func < (lhs: Severity, rhs: Severity) -> Bool { lhs.rank < rhs.rank }
}

/// Which part of OpenScout produced a finding.
public enum Engine: String, Codable, Sendable {
    case startupWatcher = "Startup watcher"
    case clamAV = "ClamAV"
    case yara = "YARA"
    case hashLookup = "Hash lookup"
    case signature = "Signature check"
    case posture = "Posture check"
}

/// Everything a finding has to carry so a person can check it without trusting OpenScout.
/// The inspector shows every field. A false-positive report includes all of them.
public struct Evidence: Codable, Equatable, Sendable {
    public var path: String
    public var sha256: String?
    public var engine: Engine
    public var ruleID: String
    public var matchDetail: String?
    public var definitionsVersion: String?
    public var signer: String?
    public var teamID: String?
    public var notarized: Bool?

    public init(path: String, sha256: String? = nil, engine: Engine, ruleID: String,
                matchDetail: String? = nil, definitionsVersion: String? = nil,
                signer: String? = nil, teamID: String? = nil, notarized: Bool? = nil) {
        self.path = path
        self.sha256 = sha256
        self.engine = engine
        self.ruleID = ruleID
        self.matchDetail = matchDetail
        self.definitionsVersion = definitionsVersion
        self.signer = signer
        self.teamID = teamID
        self.notarized = notarized
    }
}

/// One thing OpenScout wants a person to look at.
public struct Finding: Codable, Equatable, Identifiable, Sendable {
    public var id: UUID
    public var title: String
    /// One plain-English sentence on what happened.
    public var summary: String
    /// One plain-English sentence on what to do. Shown above the evidence.
    public var recommendation: String
    public var severity: Severity
    public var evidence: Evidence
    public var foundAt: Date

    public init(id: UUID = UUID(), title: String, summary: String, recommendation: String,
                severity: Severity, evidence: Evidence, foundAt: Date = Date()) {
        self.id = id
        self.title = title
        self.summary = summary
        self.recommendation = recommendation
        self.severity = severity
        self.evidence = evidence
        self.foundAt = foundAt
    }
}
