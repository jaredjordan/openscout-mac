import Foundation

public struct SignatureInfo: Codable, Equatable, Sendable {
    public var isSigned: Bool
    /// First Authority line, e.g. "Developer ID Application: Plex, Inc. (K4QJ56KR4A)".
    public var authority: String?
    public var teamID: String?
    public var notarized: Bool?

    public init(isSigned: Bool, authority: String? = nil, teamID: String? = nil, notarized: Bool? = nil) {
        self.isSigned = isSigned
        self.authority = authority
        self.teamID = teamID
        self.notarized = notarized
    }
}

/// Reads code signatures with Apple's own tools, codesign and spctl.
public struct SignatureChecker: Sendable {
    public var runner: CommandRunner
    public var codesignPath = "/usr/bin/codesign"
    public var spctlPath = "/usr/sbin/spctl"

    public init(runner: CommandRunner = ProcessCommandRunner()) {
        self.runner = runner
    }

    public func check(path: String) -> SignatureInfo {
        let sign = runner.run(codesignPath, ["-dv", "--verbose=2", "--", path], timeout: 30)
        // codesign prints signature details to stderr.
        var info = Self.parseCodesign(exitCode: sign.exitCode, output: sign.stderr + sign.stdout)
        if info.isSigned {
            let assess = runner.run(spctlPath, ["--assess", "--type", "execute", "-vv", "--", path], timeout: 30)
            info.notarized = Self.parseNotarized(assess.stderr + assess.stdout)
        } else {
            info.notarized = false
        }
        return info
    }

    public static func parseCodesign(exitCode: Int32, output: String) -> SignatureInfo {
        if exitCode != 0 || output.contains("code object is not signed at all") {
            return SignatureInfo(isSigned: false)
        }
        var authority: String?
        var teamID: String?
        for raw in output.split(whereSeparator: \.isNewline) {
            let line = String(raw)
            if authority == nil, line.hasPrefix("Authority=") {
                authority = String(line.dropFirst("Authority=".count))
            }
            if line.hasPrefix("TeamIdentifier=") {
                let value = String(line.dropFirst("TeamIdentifier=".count))
                teamID = value == "not set" ? nil : value
            }
        }
        return SignatureInfo(isSigned: true, authority: authority, teamID: teamID)
    }

    /// spctl says `source=Notarized Developer ID` for notarized apps.
    public static func parseNotarized(_ output: String) -> Bool {
        output.contains("source=Notarized Developer ID") || output.contains("source=Apple System")
    }
}
