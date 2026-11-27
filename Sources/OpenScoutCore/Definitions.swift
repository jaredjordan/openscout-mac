import Foundation

/// One downloadable set of detection data: ClamAV databases or a YARA rule pack.
public struct DefinitionManifest: Codable, Equatable, Sendable {
    public var source: String
    public var version: String
    /// File name to expected SHA-256. Every file in the set must be listed.
    public var files: [String: String]

    public init(source: String, version: String, files: [String: String]) {
        self.source = source
        self.version = version
        self.files = files
    }
}

public enum DefinitionError: Error, Equatable {
    case invalidFileName(String)
    case missingFile(String)
    case unexpectedFile(String)
    case hashMismatch(file: String, expected: String, actual: String)
    case corpusCheckFailed(newlyFlagged: [String])
    case nothingToRollBack
}

/// Five steps, every update: verify, test against a clean corpus, swap, keep the previous set,
/// record the version. Layout per source:
///
///     <root>/<source>/current    in use
///     <root>/<source>/previous   one-click rollback
///     <root>/<source>/staging    being verified
public final class DefinitionStore: @unchecked Sendable {
    public let root: URL
    private let fileManager: FileManager
    private let lock = NSLock()

    public init(root: URL, fileManager: FileManager = .default) {
        self.root = root
        self.fileManager = fileManager
    }

    public func currentDirectory(source: String) -> URL { dir(source, "current") }

    public func currentManifest(source: String) -> DefinitionManifest? {
        let url = dir(source, "current").appendingPathComponent("manifest.json")
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder.openScout.decode(DefinitionManifest.self, from: data)
    }

    /// Installs a downloaded set.
    /// - Parameters:
    ///   - downloaded: folder holding exactly the files the manifest lists.
    ///   - corpusCheck: scans the clean corpus (installed apps) with the staged set and returns
    ///     paths it flags. Anything flagged that the current set didn't flag holds the update.
    ///   - currentlyFlagged: paths the current set already flags, so they don't count as new.
    public func install(manifest: DefinitionManifest, from downloaded: URL,
                        currentlyFlagged: Set<String> = [],
                        corpusCheck: (URL) throws -> Set<String>) throws {
        lock.lock(); defer { lock.unlock() }
        let staging = dir(manifest.source, "staging")
        try? fileManager.removeItem(at: staging)
        try fileManager.createDirectory(at: staging, withIntermediateDirectories: true)

        // Step 1: verify every file against the manifest before anything is used.
        let present = Set(try fileManager.contentsOfDirectory(atPath: downloaded.path))
        for name in present where manifest.files[name] == nil {
            throw DefinitionError.unexpectedFile(name)
        }
        for (name, expected) in manifest.files.sorted(by: { $0.key < $1.key }) {
            guard Self.isSafeFileName(name) else { throw DefinitionError.invalidFileName(name) }
            let source = downloaded.appendingPathComponent(name)
            guard fileManager.fileExists(atPath: source.path) else { throw DefinitionError.missingFile(name) }
            let actual = try Hashing.sha256(fileAt: source)
            guard actual == expected.lowercased() else {
                throw DefinitionError.hashMismatch(file: name, expected: expected, actual: actual)
            }
            try fileManager.copyItem(at: source, to: staging.appendingPathComponent(name))
        }
        try JSONEncoder.openScout.encode(manifest)
            .write(to: staging.appendingPathComponent("manifest.json"), options: .atomic)

        // Step 2: a new set that flags something the current one didn't is held for a person.
        let newlyFlagged = try corpusCheck(staging).subtracting(currentlyFlagged)
        guard newlyFlagged.isEmpty else {
            try? fileManager.removeItem(at: staging)
            throw DefinitionError.corpusCheckFailed(newlyFlagged: newlyFlagged.sorted())
        }

        // Steps 3 and 4: swap by rename and keep the old set.
        let current = dir(manifest.source, "current")
        let previous = dir(manifest.source, "previous")
        try? fileManager.removeItem(at: previous)
        if fileManager.fileExists(atPath: current.path) {
            try fileManager.moveItem(at: current, to: previous)
        }
        do {
            try fileManager.moveItem(at: staging, to: current)
        } catch {
            // Never leave the source without a working set.
            if fileManager.fileExists(atPath: previous.path) {
                try? fileManager.moveItem(at: previous, to: current)
            }
            throw error
        }
    }

    /// After a crash between the two renames of a swap, `current` can be missing while
    /// `previous` holds the last good set. Call at startup. Returns true if it restored one.
    @discardableResult
    public func recoverIfNeeded(source: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        let current = dir(source, "current")
        let previous = dir(source, "previous")
        guard !fileManager.fileExists(atPath: current.path), fileManager.fileExists(atPath: previous.path) else {
            return false
        }
        return (try? fileManager.moveItem(at: previous, to: current)) != nil
    }

    /// One-click rollback to the previous set.
    public func rollback(source: String) throws {
        lock.lock(); defer { lock.unlock() }
        let current = dir(source, "current")
        let previous = dir(source, "previous")
        guard fileManager.fileExists(atPath: previous.path) else { throw DefinitionError.nothingToRollBack }
        let parked = dir(source, "rolled-back")
        try? fileManager.removeItem(at: parked)
        if fileManager.fileExists(atPath: current.path) {
            try fileManager.moveItem(at: current, to: parked)
        }
        try fileManager.moveItem(at: previous, to: current)
    }

    static func isSafeFileName(_ name: String) -> Bool {
        !name.isEmpty && name != "." && name != ".." && name != "manifest.json"
            && !name.contains("/") && !name.contains("\\") && !name.hasPrefix(".")
    }

    private func dir(_ source: String, _ slot: String) -> URL {
        let safe = source.filter { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" }
        return root.appendingPathComponent(safe, isDirectory: true).appendingPathComponent(slot, isDirectory: true)
    }
}

/// When to check each source for updates.
public struct UpdatePolicy: Sendable {
    /// ClamAV's CDN blocks clients that check more than once an hour for 24 hours.
    public static let clamAVMinimumInterval: TimeInterval = 60 * 60
    public static let clamAVCheckInterval: TimeInterval = 4 * 60 * 60
    public static let yaraCheckInterval: TimeInterval = 24 * 60 * 60
    /// Older than this and the menu bar mark changes.
    public static let staleAfter: TimeInterval = 3 * 24 * 60 * 60

    public static func shouldCheckClamAV(lastCheck: Date?, now: Date) -> Bool {
        guard let lastCheck else { return true }
        let elapsed = now.timeIntervalSince(lastCheck)
        return elapsed >= clamAVMinimumInterval && elapsed >= clamAVCheckInterval
    }

    public static func shouldCheckYARA(lastCheck: Date?, now: Date) -> Bool {
        guard let lastCheck else { return true }
        return now.timeIntervalSince(lastCheck) >= yaraCheckInterval
    }

    public static func isStale(lastUpdate: Date?, now: Date) -> Bool {
        guard let lastUpdate else { return true }
        return now.timeIntervalSince(lastUpdate) > staleAfter
    }
}
