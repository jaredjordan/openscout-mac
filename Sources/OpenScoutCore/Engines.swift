import Foundation

/// One rule or signature that matched one file.
public struct EngineMatch: Equatable, Sendable {
    public var engine: Engine
    public var path: String
    public var ruleID: String
    public var detail: String?

    public init(engine: Engine, path: String, ruleID: String, detail: String? = nil) {
        self.engine = engine
        self.path = path
        self.ruleID = ruleID
        self.detail = detail
    }
}

public enum EngineError: Error, Equatable {
    case toolMissing(String)
    case timedOut(String)
    case failed(tool: String, exitCode: Int32, stderr: String)
}

public protocol ScanEngine: Sendable {
    var engine: Engine { get }
    func scan(paths: [String]) throws -> [EngineMatch]
}

/// ClamAV, run as a separate process. The project is Apache 2.0 and ClamAV is GPLv2,
/// so OpenScout never links libclamav. See docs/decisions/0001-license-and-clamav.md.
public struct ClamAVEngine: ScanEngine {
    public let engine = Engine.clamAV
    public var clamscanPath: String
    public var databaseDirectory: String
    public var runner: CommandRunner
    public var timeout: TimeInterval

    public init(clamscanPath: String, databaseDirectory: String,
                runner: CommandRunner = ProcessCommandRunner(), timeout: TimeInterval = 600) {
        self.clamscanPath = clamscanPath
        self.databaseDirectory = databaseDirectory
        self.runner = runner
        self.timeout = timeout
    }

    public func scan(paths: [String]) throws -> [EngineMatch] {
        guard !paths.isEmpty else { return [] }
        // --no-summary keeps output to one line per infected file. "--" ends options so a
        // file named like a flag can't change behavior.
        let args = ["--no-summary", "--infected", "--database=\(databaseDirectory)", "--"] + paths
        let result = runner.run(clamscanPath, args, timeout: timeout)
        if result.timedOut { throw EngineError.timedOut("clamscan") }
        // clamscan exits 0 for clean, 1 for found, 2 for errors.
        switch result.exitCode {
        case 0: return []
        case 1: return Self.parse(result.stdout)
        case 127: throw EngineError.toolMissing(clamscanPath)
        default: throw EngineError.failed(tool: "clamscan", exitCode: result.exitCode, stderr: result.stderr)
        }
    }

    /// Lines look like: `/path/to/file: Osx.Trojan.Agent-12345 FOUND`
    public static func parse(_ output: String) -> [EngineMatch] {
        output.split(whereSeparator: \.isNewline).compactMap { raw in
            let line = String(raw)
            guard line.hasSuffix(" FOUND"), let colon = line.range(of: ": ", options: .backwards) else {
                return nil
            }
            let path = String(line[..<colon.lowerBound])
            let signature = line[colon.upperBound...].dropLast(" FOUND".count)
            guard !path.isEmpty, !signature.isEmpty else { return nil }
            return EngineMatch(engine: .clamAV, path: path, ruleID: String(signature),
                               detail: "ClamAV signature \(signature)")
        }
    }
}

/// YARA, run through the yara command-line tool with compiled macOS rules.
public struct YaraEngine: ScanEngine {
    public let engine = Engine.yara
    public var yaraPath: String
    public var rulesPath: String
    public var runner: CommandRunner
    public var timeout: TimeInterval

    public init(yaraPath: String, rulesPath: String,
                runner: CommandRunner = ProcessCommandRunner(), timeout: TimeInterval = 600) {
        self.yaraPath = yaraPath
        self.rulesPath = rulesPath
        self.runner = runner
        self.timeout = timeout
    }

    public func scan(paths: [String]) throws -> [EngineMatch] {
        var matches: [EngineMatch] = []
        for path in paths {
            // -s prints matched strings with offsets, which the inspector shows as the match.
            // -C: the rules file is precompiled. -w: no warnings mixed into output.
            let result = runner.run(yaraPath, ["-C", "-w", "-s", "--", rulesPath, path], timeout: timeout)
            if result.timedOut { throw EngineError.timedOut("yara") }
            if result.exitCode == 127 { throw EngineError.toolMissing(yaraPath) }
            guard result.exitCode == 0 else {
                throw EngineError.failed(tool: "yara", exitCode: result.exitCode, stderr: result.stderr)
            }
            matches += Self.parse(result.stdout, scannedPath: path)
        }
        return matches
    }

    /// Output looks like:
    ///
    ///     MacStealer_Generic /Users/me/Downloads/x.dmg
    ///     0x1a2b:$s1: keychain-dump
    public static func parse(_ output: String, scannedPath: String) -> [EngineMatch] {
        var matches: [EngineMatch] = []
        for raw in output.split(whereSeparator: \.isNewline) {
            let line = String(raw)
            if line.hasPrefix("0x") {
                guard !matches.isEmpty else { continue }
                let index = matches.count - 1
                let existing = matches[index].detail.map { $0 + "\n" } ?? ""
                matches[index].detail = existing + line
            } else if let space = line.firstIndex(of: " ") {
                let rule = String(line[..<space])
                let path = String(line[line.index(after: space)...])
                guard !rule.isEmpty, path == scannedPath else { continue }
                matches.append(EngineMatch(engine: .yara, path: path, ruleID: rule))
            }
        }
        return matches
    }
}

/// Turns raw engine matches into findings people can read.
public enum FindingBuilder {
    public static func finding(for match: EngineMatch, sha256: String?, definitionsVersion: String?,
                               now: Date = Date()) -> Finding {
        let name = URL(fileURLWithPath: match.path).lastPathComponent
        return Finding(
            title: "Known malware pattern in \(name)",
            summary: "\(name) matches \(match.engine.rawValue) rule \(match.ruleID).",
            recommendation: "Recommended: Quarantine. You can undo this.",
            severity: .high,
            evidence: Evidence(path: match.path, sha256: sha256, engine: match.engine, ruleID: match.ruleID,
                               matchDetail: match.detail, definitionsVersion: definitionsVersion),
            foundAt: now)
    }

    public static func finding(forNewStartupItem item: StartupItem, signature: SignatureInfo?,
                               now: Date = Date()) -> Finding {
        let unsigned = signature?.isSigned == false
        let suspicious = item.programInSuspiciousLocation
        let severity: Severity = (unsigned && suspicious) ? .high : (unsigned || suspicious) ? .medium : .low
        let title = unsigned ? "Unsigned startup item" : "New startup item"
        var summary = "\(item.label) will run \(item.program ?? "a program") "
        summary += item.runAtLoad || item.keepAlive ? "every time you log in." : "when launchd starts it."
        if unsigned { summary += " Nobody signed it." }
        if suspicious { summary += " It runs from a temporary or hidden folder." }
        let ruleID = unsigned ? "OS-STARTUP-0004" : (suspicious ? "OS-STARTUP-0002" : "OS-STARTUP-0001")
        return Finding(
            title: title,
            summary: summary,
            recommendation: severity >= .medium ? "Recommended: Quarantine. You can undo this."
                                                : "Recommended: Review it. Allow it if you installed it.",
            severity: severity,
            evidence: Evidence(path: item.plistPath, sha256: item.plistSHA256, engine: .startupWatcher,
                               ruleID: ruleID, matchDetail: item.program.map { "Runs \($0)" },
                               signer: signature?.authority, teamID: signature?.teamID,
                               notarized: signature?.notarized),
            foundAt: now)
    }
}
