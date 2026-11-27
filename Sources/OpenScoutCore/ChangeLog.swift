import Foundation

/// One release in CHANGELOG.md. The in-app Changes view reads the same file,
/// so the app and the repository can never tell different stories.
public struct ChangeLogRelease: Equatable, Sendable {
    public var version: String
    public var date: String?
    public var sections: [String: [String]]

    public init(version: String, date: String?, sections: [String: [String]]) {
        self.version = version
        self.date = date
        self.sections = sections
    }
}

public enum ChangeLogParser {
    /// Parses Keep a Changelog markdown:
    ///
    ///     ## [0.2.0] - 2026-12-07
    ///     ### Added
    ///     - Something.
    public static func parse(_ markdown: String) -> [ChangeLogRelease] {
        var releases: [ChangeLogRelease] = []
        var current: ChangeLogRelease?
        var section: String?
        for raw in markdown.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("## ") {
                if let current { releases.append(current) }
                let heading = String(line.dropFirst(3))
                let (version, date) = splitHeading(heading)
                current = ChangeLogRelease(version: version, date: date, sections: [:])
                section = nil
            } else if line.hasPrefix("### ") {
                section = String(line.dropFirst(4))
            } else if line.hasPrefix("- "), let name = section, current != nil {
                current?.sections[name, default: []].append(String(line.dropFirst(2)))
            }
        }
        if let current { releases.append(current) }
        return releases
    }

    static func splitHeading(_ heading: String) -> (String, String?) {
        var version = heading
        var date: String?
        if let dash = heading.range(of: " - ") {
            version = String(heading[..<dash.lowerBound])
            date = String(heading[dash.upperBound...])
        }
        version = version.trimmingCharacters(in: CharacterSet(charactersIn: "[] "))
        return (version, date)
    }
}
