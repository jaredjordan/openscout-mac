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

/// What one engine found, plus anything that went wrong. Matches are never thrown away
/// because another file in the same batch failed.
public struct EngineScanResult: Equatable, Sendable {
    public var matches: [EngineMatch]
    /// Problems that mean some files weren't fully scanned. Never reported as clean.
    public var errors: [String]
    /// Files the engine skipped by design (for example over ClamAV's size limit).
    public var skipped: [String]

    public init(matches: [EngineMatch] = [], errors: [String] = [], skipped: [String] = []) {
        self.matches = matches
        self.errors = errors
        self.skipped = skipped
    }
}

public protocol ScanEngine: Sendable {
    var engine: Engine { get }
    /// - Parameter recursive: scan inside folders and app bundles passed in `paths`.
    func scan(paths: [String], recursive: Bool) -> EngineScanResult
}

public extension ScanEngine {
    func scan(paths: [String]) -> EngineScanResult { scan(paths: paths, recursive: false) }
}

/// True when `path` is one of the inputs, or inside one of them for a recursive scan.
func isWithin(_ path: String, inputs: Set<String>, recursive: Bool) -> Bool {
    if inputs.contains(path) { return true }
    guard recursive else { return false }
    return inputs.contains { path.hasPrefix($0.hasSuffix("/") ? $0 : $0 + "/") }
}

/// ClamAV, run as a separate process. The project is Apache 2.0 and ClamAV is GPLv2,
/// so OpenScout never links libclamav. See docs/decisions/0001-license-and-clamav.md.
public struct ClamAVEngine: ScanEngine {
    public let engine = Engine.clamAV
    public var clamscanPath: String
    public var databaseDirectory: String
    public var runner: CommandRunner
    public var timeout: TimeInterval

    /// Prefix of ClamAV's own "file too big to scan fully" alerts.
    static let limitsPrefix = "Heuristics.Limits.Exceeded"

    public init(clamscanPath: String, databaseDirectory: String,
                runner: CommandRunner = ProcessCommandRunner(), timeout: TimeInterval = 600) {
        self.clamscanPath = clamscanPath
        self.databaseDirectory = databaseDirectory
        self.runner = runner
        self.timeout = timeout
    }

    public static func arguments(databaseDirectory: String, recursive: Bool, paths: [String]) -> [String] {
        // Raised size limits plus --alert-exceeds-max, so a file padded past the limit is
        // reported as not fully scanned instead of passing silently. "--" ends options so a
        // file named like a flag can't change behavior.
        ["--no-summary", "--infected", "--max-filesize=512M", "--max-scansize=1024M",
         "--alert-exceeds-max=yes", "--database=\(databaseDirectory)"]
            + (recursive ? ["--recursive"] : []) + ["--"] + paths
    }

    public func scan(paths: [String], recursive: Bool) -> EngineScanResult {
        guard !paths.isEmpty else { return EngineScanResult() }
        // A path with a newline can forge output lines for its neighbors, so each one is
        // scanned alone and any detection is attributed to it directly.
        let unsafe = paths.filter { $0.contains("\n") || $0.contains("\r") }
        let normal = paths.filter { !unsafe.contains($0) }
        var out = normal.isEmpty ? EngineScanResult() : scanBatch(normal, recursive: recursive)
        for path in unsafe {
            let single = scanSingleUnsafe(path)
            out.matches += single.matches
            out.errors += single.errors
            out.skipped += single.skipped
        }
        return out
    }

    private func scanBatch(_ paths: [String], recursive: Bool) -> EngineScanResult {
        let args = Self.arguments(databaseDirectory: databaseDirectory, recursive: recursive, paths: paths)
        let result = runner.run(clamscanPath, args, timeout: timeout)
        if result.timedOut { return EngineScanResult(errors: ["clamscan timed out"]) }
        if result.exitCode == 127 { return EngineScanResult(errors: ["clamscan isn't installed at \(clamscanPath)"]) }
        // clamscan exits 0 for clean, 1 for found, 2 for errors. Matches are parsed in every
        // case: one unreadable file must not hide detections in the rest of the batch.
        let inputs = Set(paths)
        let parsed = Self.parse(result.stdout).filter { isWithin($0.path, inputs: inputs, recursive: recursive) }
        var out = EngineScanResult()
        for match in parsed {
            if match.ruleID.hasPrefix(Self.limitsPrefix) { out.skipped.append(match.path) } else { out.matches.append(match) }
        }
        switch result.exitCode {
        case 0:
            break
        case 1:
            if parsed.isEmpty { out.errors.append("clamscan reported a detection OpenScout couldn't match to a file") }
        default:
            // Files that vanished or can't be read are routine in Downloads and home folders.
            // They're listed as skipped. Anything else is a real engine failure.
            let (unreadable, other) = Self.classifyProblems(result.stdout + "\n" + result.stderr,
                                                            inputs: inputs, recursive: recursive)
            out.skipped += unreadable
            if !other.isEmpty || unreadable.isEmpty {
                out.errors.append("clamscan exited \(result.exitCode): \(other.joined(separator: "; ").prefix(300))")
            }
        }
        return out
    }

    private func scanSingleUnsafe(_ path: String) -> EngineScanResult {
        let args = Self.arguments(databaseDirectory: databaseDirectory, recursive: false, paths: [path])
        let result = runner.run(clamscanPath, args, timeout: timeout)
        if result.timedOut { return EngineScanResult(errors: ["clamscan timed out"]) }
        switch result.exitCode {
        case 0:
            return EngineScanResult()
        case 1:
            // One input, so any detection belongs to it. The signature is on the last FOUND line.
            let last = result.stdout.split(whereSeparator: \.isNewline).last { $0.hasSuffix(" FOUND") }
            let signature = last.flatMap { line -> String? in
                guard let colon = line.range(of: ": ", options: .backwards) else { return nil }
                return String(line[colon.upperBound...].dropLast(" FOUND".count))
            } ?? "Unknown"
            if signature.hasPrefix(Self.limitsPrefix) { return EngineScanResult(skipped: [path]) }
            return EngineScanResult(matches: [EngineMatch(engine: .clamAV, path: path, ruleID: signature,
                                                          detail: "ClamAV signature \(signature)")])
        default:
            return EngineScanResult(errors: ["clamscan exited \(result.exitCode) on a file with a newline in its name"])
        }
    }

    static let unreadableMarkers = ["Access denied", "Permission denied", "No such file or directory",
                                    "Can't open file or directory", "Can't access file"]

    /// Splits clamscan's problem lines into per-file read problems (skipped) and everything else.
    public static func classifyProblems(_ output: String, inputs: Set<String>, recursive: Bool) -> (unreadable: [String], other: [String]) {
        var unreadable: [String] = []
        var other: [String] = []
        for raw in output.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasSuffix(" FOUND"), !line.hasSuffix(": OK") else { continue }
            if unreadableMarkers.contains(where: { line.contains($0) }) {
                var body = line
                if body.hasPrefix("WARNING: ") { body.removeFirst("WARNING: ".count) }
                if let colon = body.range(of: ": "), isWithin(String(body[..<colon.lowerBound]), inputs: inputs, recursive: recursive) {
                    unreadable.append(String(body[..<colon.lowerBound]))
                    continue
                }
            }
            other.append(line)
        }
        return (unreadable, other)
    }

    /// Lines look like: `/path/to/file: Osx.Trojan.Agent-12345 FOUND`.
    /// Only paths that match an input survive, so a crafted file name can't redirect a finding.
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

    public func scan(paths: [String], recursive: Bool) -> EngineScanResult {
        var out = EngineScanResult()
        for path in paths {
            // -s prints matched strings with offsets, which the inspector shows as the match.
            // -C: the rules file is precompiled. -w: no warnings mixed into output.
            var args = ["-C", "-w", "-s"]
            if recursive { args.append("-r") }
            args += ["--", rulesPath, path]
            let result = runner.run(yaraPath, args, timeout: timeout)
            if result.timedOut { out.errors.append("yara timed out on a file"); continue }
            if result.exitCode == 127 { out.errors.append("yara isn't installed at \(yaraPath)"); break }
            guard result.exitCode == 0 else {
                out.errors.append("yara exited \(result.exitCode): \(result.stderr.prefix(300))")
                continue
            }
            let matches = Self.parse(result.stdout, scannedPath: path, recursive: recursive)
            let printable = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if matches.isEmpty && !printable.isEmpty {
                // Output we couldn't attribute, for example a file name with a newline in it.
                out.errors.append("yara output couldn't be matched to a file")
            }
            out.matches += matches
        }
        return out
    }

    /// Output looks like:
    ///
    ///     MacStealer_Generic /Users/me/Downloads/x.dmg
    ///     0x1a2b:$s1: keychain-dump
    public static func parse(_ output: String, scannedPath: String, recursive: Bool = false) -> [EngineMatch] {
        var matches: [EngineMatch] = []
        let inputs: Set<String> = [scannedPath]
        var lastWasMatch = false
        for raw in output.split(whereSeparator: \.isNewline) {
            let line = String(raw)
            if line.hasPrefix("0x") {
                guard lastWasMatch, !matches.isEmpty else { continue }
                let index = matches.count - 1
                let existing = matches[index].detail.map { $0 + "\n" } ?? ""
                matches[index].detail = existing + line
            } else if let space = line.firstIndex(of: " ") {
                let rule = String(line[..<space])
                let path = String(line[line.index(after: space)...])
                guard !rule.isEmpty, isWithin(path, inputs: inputs, recursive: recursive) else {
                    lastWasMatch = false
                    continue
                }
                matches.append(EngineMatch(engine: .yara, path: path, ruleID: rule))
                lastWasMatch = true
            } else {
                lastWasMatch = false
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

    /// A file in a watched folder that couldn't be read or fully scanned. Shown for review
    /// rather than passed as clean, since unreadable payloads are a way to hide.
    public static func finding(forUnscannable path: String, now: Date = Date()) -> Finding {
        let name = URL(fileURLWithPath: path).lastPathComponent
        return Finding(
            title: "Couldn't scan \(name)",
            summary: "OpenScout couldn't read all of \(name), so it hasn't been checked.",
            recommendation: "Recommended: Review it. Delete it yourself if you don't recognize it, or quarantine it.",
            severity: .low,
            evidence: Evidence(path: path, engine: .clamAV, ruleID: "OS-SCAN-0001",
                               matchDetail: "Unreadable or over the size limit"),
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
