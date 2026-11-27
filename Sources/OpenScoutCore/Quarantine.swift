import Foundation

/// A file OpenScout moved out of the way. Nothing is ever deleted.
public struct QuarantineRecord: Codable, Equatable, Identifiable, Sendable {
    public var id: UUID
    public var originalPath: String
    public var originalPermissions: Int
    public var sha256: String
    public var quarantinedAt: Date
    /// The finding that caused the move, with its full evidence, so a false-positive report has it.
    public var finding: Finding

    public init(id: UUID, originalPath: String, originalPermissions: Int, sha256: String,
                quarantinedAt: Date, finding: Finding) {
        self.id = id
        self.originalPath = originalPath
        self.originalPermissions = originalPermissions
        self.sha256 = sha256
        self.quarantinedAt = quarantinedAt
        self.finding = finding
    }
}

public enum QuarantineError: Error, Equatable {
    case sourceMissing(String)
    case notARegularFile(String)
    case recordMissing(UUID)
    case destinationOccupied(String)
    case payloadChanged(UUID)
}

/// Layout on disk, all owner-only (0700 folders, 0400 payloads):
///
///     <root>/<uuid>/payload        the file, read-only, never executable
///     <root>/<uuid>/record.json    where it came from and why
public final class QuarantineStore: @unchecked Sendable {
    public let root: URL
    private let fileManager: FileManager
    private let lock = NSLock()

    public init(root: URL, fileManager: FileManager = .default) throws {
        self.root = root
        self.fileManager = fileManager
        try fileManager.createDirectory(at: root, withIntermediateDirectories: true,
                                        attributes: [.posixPermissions: 0o700])
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
    }

    @discardableResult
    public func quarantine(fileAt url: URL, finding: Finding, now: Date = Date()) throws -> QuarantineRecord {
        lock.lock(); defer { lock.unlock() }
        let path = url.path
        guard let attrs = try? fileManager.attributesOfItem(atPath: path) else {
            throw QuarantineError.sourceMissing(path)
        }
        // Only regular files. A symlink would let an attacker point the move at something else.
        guard (attrs[.type] as? FileAttributeType) == .typeRegular else {
            throw QuarantineError.notARegularFile(path)
        }
        let permissions = (attrs[.posixPermissions] as? NSNumber)?.intValue ?? 0o644
        let sha = try Hashing.sha256(fileAt: url)

        let id = UUID()
        let folder = root.appendingPathComponent(id.uuidString, isDirectory: true)
        try fileManager.createDirectory(at: folder, withIntermediateDirectories: false,
                                        attributes: [.posixPermissions: 0o700])
        let payload = folder.appendingPathComponent("payload")
        try fileManager.moveItem(at: url, to: payload)
        try fileManager.setAttributes([.posixPermissions: 0o400], ofItemAtPath: payload.path)

        let record = QuarantineRecord(id: id, originalPath: path, originalPermissions: permissions,
                                      sha256: sha, quarantinedAt: now, finding: finding)
        try JSONEncoder.openScout.encode(record)
            .write(to: folder.appendingPathComponent("record.json"), options: .atomic)
        return record
    }

    public func records() -> [QuarantineRecord] {
        lock.lock(); defer { lock.unlock() }
        guard let names = try? fileManager.contentsOfDirectory(atPath: root.path) else { return [] }
        return names.compactMap { name -> QuarantineRecord? in
            guard UUID(uuidString: name) != nil else { return nil }
            let url = root.appendingPathComponent(name).appendingPathComponent("record.json")
            guard let data = try? Data(contentsOf: url) else { return nil }
            return try? JSONDecoder.openScout.decode(QuarantineRecord.self, from: data)
        }.sorted { $0.quarantinedAt > $1.quarantinedAt }
    }

    /// Puts the file back with its original permissions. Refuses to overwrite anything,
    /// and refuses if the quarantined bytes changed since they were moved.
    @discardableResult
    public func restore(id: UUID) throws -> QuarantineRecord {
        lock.lock(); defer { lock.unlock() }
        let folder = root.appendingPathComponent(id.uuidString, isDirectory: true)
        let recordURL = folder.appendingPathComponent("record.json")
        guard let data = try? Data(contentsOf: recordURL),
              let record = try? JSONDecoder.openScout.decode(QuarantineRecord.self, from: data) else {
            throw QuarantineError.recordMissing(id)
        }
        let payload = folder.appendingPathComponent("payload")
        guard (try? Hashing.sha256(fileAt: payload)) == record.sha256 else {
            throw QuarantineError.payloadChanged(id)
        }
        if fileManager.fileExists(atPath: record.originalPath) {
            throw QuarantineError.destinationOccupied(record.originalPath)
        }
        let destination = URL(fileURLWithPath: record.originalPath)
        try fileManager.createDirectory(at: destination.deletingLastPathComponent(),
                                        withIntermediateDirectories: true)
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: payload.path)
        try fileManager.moveItem(at: payload, to: destination)
        try fileManager.setAttributes([.posixPermissions: record.originalPermissions],
                                      ofItemAtPath: destination.path)
        try fileManager.removeItem(at: folder)
        return record
    }
}
