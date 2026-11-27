import Foundation

public struct ScanReport: Equatable, Sendable {
    public var scannedFiles: Int
    public var findings: [Finding]
    /// Engines that failed. A failed engine is reported, never treated as "nothing found".
    public var engineErrors: [String]
    /// Files skipped by design, such as files over ClamAV's size limit. Shown, not hidden.
    public var skipped: [String] = []

    public var isClean: Bool { findings.isEmpty && engineErrors.isEmpty }
}

/// Runs every engine over a set of files and turns matches into findings.
public struct ScanService: Sendable {
    public var engines: [ScanEngine]
    public var allowStore: AllowStore?
    public var definitionsVersion: String?

    public init(engines: [ScanEngine], allowStore: AllowStore? = nil, definitionsVersion: String? = nil) {
        self.engines = engines
        self.allowStore = allowStore
        self.definitionsVersion = definitionsVersion
    }

    public static let noEnginesError = "No scan engine is available. Install ClamAV and download definitions."

    public func scan(paths: [String], now: Date = Date()) -> ScanReport {
        // With no engine, nothing was scanned. That must never read as clean.
        guard !engines.isEmpty else {
            return ScanReport(scannedFiles: 0, findings: [], engineErrors: [Self.noEnginesError])
        }
        var findings: [Finding] = []
        var errors: [String] = []
        var skipped: [String] = []
        var hashes: [String: String] = [:]
        for engine in engines {
            let result = engine.scan(paths: paths)
            errors += result.errors.map { "\(engine.engine.rawValue): \($0)" }
            skipped += result.skipped
            for match in result.matches {
                let sha = hashes[match.path] ?? (try? Hashing.sha256(fileAt: URL(fileURLWithPath: match.path)))
                hashes[match.path] = sha
                if let sha, allowStore?.isAllowed(path: match.path, sha256: sha) == true { continue }
                findings.append(FindingBuilder.finding(for: match, sha256: sha,
                                                       definitionsVersion: definitionsVersion, now: now))
            }
        }
        return ScanReport(scannedFiles: paths.count, findings: findings, engineErrors: errors,
                          skipped: Array(Set(skipped)).sorted())
    }
}

/// Which files a quick scan covers. Full scans walk the whole disk in the helper.
public enum ScanTargets {
    public static func quickScanRoots(home: URL) -> [URL] {
        [
            URL(fileURLWithPath: "/Applications", isDirectory: true),
            home.appendingPathComponent("Applications", isDirectory: true),
            home.appendingPathComponent("Downloads", isDirectory: true),
        ]
    }

    /// Partial downloads are skipped until the browser finishes writing them.
    public static func isPartialDownload(_ path: String) -> Bool {
        let partial = [".crdownload", ".download", ".part", ".partial", ".opdownload"]
        return partial.contains { path.lowercased().hasSuffix($0) }
    }
}
