import Foundation

/// Files the user has allowed. An entry matches only the exact bytes that were allowed:
/// if the file changes, its hash changes and OpenScout checks it again.
public struct AllowEntry: Codable, Equatable, Sendable {
    public var path: String
    public var sha256: String
    public var allowedAt: Date
    /// Why it was allowed, shown in the Changes view and the inspector.
    public var reason: String

    public init(path: String, sha256: String, allowedAt: Date = Date(), reason: String) {
        self.path = path
        self.sha256 = sha256
        self.allowedAt = allowedAt
        self.reason = reason
    }
}

public final class AllowStore: @unchecked Sendable {
    private let fileURL: URL
    private let lock = NSLock()
    private var entries: [AllowEntry]

    public init(fileURL: URL) {
        self.fileURL = fileURL
        if let data = try? Data(contentsOf: fileURL),
           let decoded = try? JSONDecoder.openScout.decode([AllowEntry].self, from: data) {
            entries = decoded
        } else {
            entries = []
        }
    }

    public var all: [AllowEntry] {
        lock.lock(); defer { lock.unlock() }
        return entries
    }

    public func isAllowed(path: String, sha256: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return entries.contains { $0.path == path && $0.sha256 == sha256 }
    }

    /// Allowing is the second step of a two-step action. The UI must show the consequence
    /// and get confirmation before calling this.
    public func allow(_ entry: AllowEntry) throws {
        lock.lock(); defer { lock.unlock() }
        entries.removeAll { $0.path == entry.path }
        entries.append(entry)
        try persist()
    }

    public func revoke(path: String) throws {
        lock.lock(); defer { lock.unlock() }
        entries.removeAll { $0.path == path }
        try persist()
    }

    private func persist() throws {
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        let data = try JSONEncoder.openScout.encode(entries)
        try data.write(to: fileURL, options: .atomic)
    }
}

extension JSONEncoder {
    static var openScout: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return encoder
    }
}

extension JSONDecoder {
    static var openScout: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}
