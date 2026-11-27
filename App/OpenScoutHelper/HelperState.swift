import Foundation
import OpenScoutCore
import OpenScoutMac

/// Everything the helper persists between launches.
struct PersistedState: Codable {
    var findings: [Finding] = []
    var startupBaseline: [StartupItem] = []
    var lastQuickScan: Date?
    var lastFullScan: Date?
    var lastClamAVCheck: Date?
    var lastDefinitionsUpdate: Date?
    var settings = ScanSettings()
    var activity: [ActivityEntry] = []
}

/// Where OpenScout keeps its data. Owner-only.
enum Paths {
    static let fileManager = FileManager.default

    static var support: URL {
        let base = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("OpenScout", isDirectory: true)
    }

    static var state: URL { support.appendingPathComponent("state.json") }
    static var allowList: URL { support.appendingPathComponent("allow.json") }
    static var quarantine: URL { support.appendingPathComponent("Quarantine", isDirectory: true) }
    static var definitions: URL { support.appendingPathComponent("Definitions", isDirectory: true) }
    static var home: URL { fileManager.homeDirectoryForCurrentUser }
    static var downloads: URL { home.appendingPathComponent("Downloads", isDirectory: true) }

    /// Version 1 uses ClamAV and YARA installed with Homebrew. Bundling them is tracked separately.
    static func tool(_ name: String) -> String? {
        ["/opt/homebrew/bin", "/usr/local/bin"].map { "\($0)/\(name)" }
            .first { fileManager.isExecutableFile(atPath: $0) }
    }

    static func ensure() throws {
        try fileManager.createDirectory(at: support, withIntermediateDirectories: true,
                                        attributes: [.posixPermissions: 0o700])
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: support.path)
    }
}

/// Serializes all state changes on one queue. Saved after every change.
final class StateStore: @unchecked Sendable {
    private let queue = DispatchQueue(label: "openscout.state")
    private var state: PersistedState

    init() {
        if let data = try? Data(contentsOf: Paths.state),
           let decoded = try? Self.decoder.decode(PersistedState.self, from: data) {
            state = decoded
        } else {
            state = PersistedState()
        }
    }

    func read<T>(_ body: (PersistedState) -> T) -> T { queue.sync { body(state) } }

    func update(_ body: (inout PersistedState) -> Void) {
        queue.sync {
            body(&state)
            state.activity = Array(state.activity.suffix(200))
            if let data = try? Self.encoder.encode(state) {
                try? data.write(to: Paths.state, options: .atomic)
            }
        }
    }

    func log(_ text: String) {
        update { $0.activity.append(ActivityEntry(text: text)) }
    }

    static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        return e
    }()

    static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()
}
