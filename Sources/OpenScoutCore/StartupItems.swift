import Foundation

/// A launchd job that starts on its own: a LaunchAgent or LaunchDaemon property list.
public struct StartupItem: Codable, Equatable, Hashable, Sendable {
    public var plistPath: String
    public var label: String
    /// The program launchd will run, resolved from Program or ProgramArguments[0].
    public var program: String?
    public var arguments: [String]
    public var runAtLoad: Bool
    public var keepAlive: Bool
    /// SHA-256 of the property list itself, so a changed plist is noticed.
    public var plistSHA256: String

    public init(plistPath: String, label: String, program: String?, arguments: [String],
                runAtLoad: Bool, keepAlive: Bool, plistSHA256: String) {
        self.plistPath = plistPath
        self.label = label
        self.program = program
        self.arguments = arguments
        self.runAtLoad = runAtLoad
        self.keepAlive = keepAlive
        self.plistSHA256 = plistSHA256
    }

    /// Programs in world-writable or temporary places are a common malware pattern.
    public var programInSuspiciousLocation: Bool {
        guard let program else { return false }
        let suspicious = ["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/Users/Shared/"]
        if suspicious.contains(where: { program.hasPrefix($0) }) { return true }
        // Hidden directories anywhere in the path, e.g. ~/.local/.x/helper
        return program.split(separator: "/").dropLast().contains { $0.hasPrefix(".") }
    }
}

public enum StartupItemError: Error, Equatable {
    case unreadable(String)
    case notADictionary(String)
    case missingLabel(String)
}

public enum StartupItemParser {
    public static func parse(plistAt url: URL) throws -> StartupItem {
        guard let data = try? Data(contentsOf: url) else {
            throw StartupItemError.unreadable(url.path)
        }
        return try parse(data: data, path: url.path)
    }

    public static func parse(data: Data, path: String) throws -> StartupItem {
        let object: Any
        do {
            object = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        } catch {
            throw StartupItemError.unreadable(path)
        }
        guard let dict = object as? [String: Any] else { throw StartupItemError.notADictionary(path) }
        guard let label = dict["Label"] as? String, !label.isEmpty else {
            throw StartupItemError.missingLabel(path)
        }
        let arguments = (dict["ProgramArguments"] as? [Any])?.compactMap { $0 as? String } ?? []
        let program = (dict["Program"] as? String) ?? arguments.first
        let runAtLoad = dict["RunAtLoad"] as? Bool ?? false
        let keepAlive: Bool
        if let flag = dict["KeepAlive"] as? Bool {
            keepAlive = flag
        } else {
            keepAlive = dict["KeepAlive"] is [String: Any]
        }
        return StartupItem(plistPath: path, label: label, program: program, arguments: arguments,
                           runAtLoad: runAtLoad, keepAlive: keepAlive,
                           plistSHA256: Hashing.sha256(data: data))
    }
}

/// The folders launchd reads startup items from.
public enum StartupLocations {
    public static func standard(home: URL) -> [URL] {
        [
            home.appendingPathComponent("Library/LaunchAgents", isDirectory: true),
            URL(fileURLWithPath: "/Library/LaunchAgents", isDirectory: true),
            URL(fileURLWithPath: "/Library/LaunchDaemons", isDirectory: true),
        ]
    }
}

public struct StartupScanResult: Equatable, Sendable {
    public var items: [StartupItem]
    /// Plists that couldn't be parsed. Reported, never silently skipped.
    public var unreadable: [String]
}

public enum StartupItemScanner {
    public static func scan(directories: [URL], fileManager: FileManager = .default) -> StartupScanResult {
        var items: [StartupItem] = []
        var unreadable: [String] = []
        for dir in directories {
            guard let names = try? fileManager.contentsOfDirectory(atPath: dir.path) else { continue }
            for name in names.sorted() where name.hasSuffix(".plist") {
                let url = dir.appendingPathComponent(name)
                do {
                    items.append(try StartupItemParser.parse(plistAt: url))
                } catch {
                    unreadable.append(url.path)
                }
            }
        }
        return StartupScanResult(items: items, unreadable: unreadable)
    }
}

/// What changed between two scans. The watcher alerts on `added` and `changed`.
public struct StartupDiff: Equatable, Sendable {
    public var added: [StartupItem]
    public var changed: [StartupItem]
    public var removed: [StartupItem]

    public var isEmpty: Bool { added.isEmpty && changed.isEmpty && removed.isEmpty }

    public static func between(old: [StartupItem], new: [StartupItem]) -> StartupDiff {
        let oldByPath = Dictionary(old.map { ($0.plistPath, $0) }, uniquingKeysWith: { a, _ in a })
        let newByPath = Dictionary(new.map { ($0.plistPath, $0) }, uniquingKeysWith: { a, _ in a })
        let added = new.filter { oldByPath[$0.plistPath] == nil }
        let removed = old.filter { newByPath[$0.plistPath] == nil }
        let changed = new.filter { item in
            guard let before = oldByPath[item.plistPath] else { return false }
            return before.plistSHA256 != item.plistSHA256
        }
        return StartupDiff(added: added, changed: changed, removed: removed)
    }
}
