import Foundation

public enum PostureCheckID: String, Codable, CaseIterable, Sendable {
    case gatekeeper, sip, fileVault, firewall
}

public struct PostureResult: Codable, Equatable, Sendable {
    public var check: PostureCheckID
    /// nil when the state couldn't be read. Shown as "Unknown", never as on.
    public var enabled: Bool?
    public var howToFix: String

    public init(check: PostureCheckID, enabled: Bool?, howToFix: String) {
        self.check = check
        self.enabled = enabled
        self.howToFix = howToFix
    }
}

/// Checks that macOS's own protections are on.
public struct PostureChecker: Sendable {
    public var runner: CommandRunner

    public init(runner: CommandRunner = ProcessCommandRunner()) {
        self.runner = runner
    }

    public func runAll() -> [PostureResult] {
        [
            PostureResult(check: .gatekeeper,
                          enabled: Self.parseGatekeeper(runner.run("/usr/sbin/spctl", ["--status"], timeout: 10)),
                          howToFix: "Open System Settings > Privacy & Security and allow apps from the App Store and identified developers."),
            PostureResult(check: .sip,
                          enabled: Self.parseSIP(runner.run("/usr/bin/csrutil", ["status"], timeout: 10)),
                          howToFix: "System Integrity Protection can only be turned back on from macOS Recovery with `csrutil enable`."),
            PostureResult(check: .fileVault,
                          enabled: Self.parseFileVault(runner.run("/usr/bin/fdesetup", ["status"], timeout: 10)),
                          howToFix: "Open System Settings > Privacy & Security > FileVault and turn it on."),
            PostureResult(check: .firewall,
                          enabled: Self.parseFirewall(runner.run("/usr/libexec/ApplicationFirewall/socketfilterfw",
                                                                 ["--getglobalstate"], timeout: 10)),
                          howToFix: "Open System Settings > Network > Firewall and turn it on."),
        ]
    }

    static func text(_ r: CommandResult) -> String? {
        guard !r.timedOut, r.exitCode != 127, r.exitCode != 126 else { return nil }
        return (r.stdout + r.stderr).lowercased()
    }

    public static func parseGatekeeper(_ r: CommandResult) -> Bool? {
        guard let t = text(r) else { return nil }
        if t.contains("assessments enabled") { return true }
        if t.contains("assessments disabled") { return false }
        return nil
    }

    public static func parseSIP(_ r: CommandResult) -> Bool? {
        guard let t = text(r) else { return nil }
        if t.contains("status: enabled") { return true }
        if t.contains("status: disabled") { return false }
        return nil
    }

    public static func parseFileVault(_ r: CommandResult) -> Bool? {
        guard let t = text(r) else { return nil }
        if t.contains("filevault is on") { return true }
        if t.contains("filevault is off") { return false }
        return nil
    }

    public static func parseFirewall(_ r: CommandResult) -> Bool? {
        guard let t = text(r) else { return nil }
        if t.contains("enabled") && !t.contains("disabled") { return true }
        if t.contains("disabled") { return false }
        return nil
    }
}

/// Full Disk Access can't be queried directly. The reliable test is whether a folder macOS
/// protects can be listed. Without access, OpenScout must say "Not fully protected".
public enum FullDiskAccessProbe {
    public static func protectedPaths(home: URL) -> [URL] {
        [
            home.appendingPathComponent("Library/Mail"),
            home.appendingPathComponent("Library/Messages"),
            home.appendingPathComponent("Library/Safari"),
        ]
    }

    /// true: access granted. false: denied. nil: none of the probe folders exist, so unknown.
    public static func hasAccess(home: URL, fileManager: FileManager = .default) -> Bool? {
        var sawFolder = false
        for url in protectedPaths(home: home) {
            var isDir: ObjCBool = false
            guard fileManager.fileExists(atPath: url.path, isDirectory: &isDir), isDir.boolValue else { continue }
            sawFolder = true
            if (try? fileManager.contentsOfDirectory(atPath: url.path)) != nil { return true }
        }
        return sawFolder ? false : nil
    }
}
