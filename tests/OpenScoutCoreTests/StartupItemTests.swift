import Foundation
import XCTest
@testable import OpenScoutCore

final class StartupItemTests: XCTestCase {
    func testParsesFixtureAndFlagsHiddenTmpProgram() throws {
        let item = try StartupItemParser.parse(plistAt: fixture("com.update.helper.plist"))
        XCTAssertEqual(item.label, "com.update.helper")
        XCTAssertEqual(item.program, "/tmp/.u/helper")
        XCTAssertEqual(item.arguments, ["/tmp/.u/helper", "--quiet"])
        XCTAssertTrue(item.runAtLoad)
        XCTAssertFalse(item.keepAlive)
        XCTAssertTrue(item.programInSuspiciousLocation)
        XCTAssertEqual(item.plistSHA256.count, 64)
    }

    func testProgramKeyWinsOverArguments() throws {
        let plist: [String: Any] = ["Label": "a", "Program": "/usr/local/bin/a", "ProgramArguments": ["/other"]]
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        let item = try StartupItemParser.parse(data: data, path: "/x.plist")
        XCTAssertEqual(item.program, "/usr/local/bin/a")
        XCTAssertFalse(item.programInSuspiciousLocation)
    }

    func testKeepAliveDictionaryCountsAsKeepAlive() throws {
        let plist: [String: Any] = ["Label": "a", "Program": "/bin/a", "KeepAlive": ["SuccessfulExit": false]]
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        XCTAssertTrue(try StartupItemParser.parse(data: data, path: "/x.plist").keepAlive)
    }

    func testMissingLabelIsAnError() throws {
        let data = try PropertyListSerialization.data(fromPropertyList: ["Program": "/bin/a"], format: .xml, options: 0)
        XCTAssertThrowsError(try StartupItemParser.parse(data: data, path: "/x.plist")) {
            XCTAssertEqual($0 as? StartupItemError, .missingLabel("/x.plist"))
        }
    }

    func testScannerReportsUnreadablePlistsInsteadOfSkipping() throws {
        let dir = try makeTempDir()
        try FileManager.default.copyItem(at: fixture("com.update.helper.plist"),
                                         to: dir.appendingPathComponent("good.plist"))
        try Data("not a plist".utf8).write(to: dir.appendingPathComponent("bad.plist"))
        try Data("ignored".utf8).write(to: dir.appendingPathComponent("notes.txt"))
        let result = StartupItemScanner.scan(directories: [dir, dir.appendingPathComponent("missing")])
        XCTAssertEqual(result.items.map(\.label), ["com.update.helper"])
        XCTAssertEqual(result.unreadable, [dir.appendingPathComponent("bad.plist").path])
    }

    func testDiffFindsAddedChangedRemoved() {
        func item(_ path: String, _ sha: String) -> StartupItem {
            StartupItem(plistPath: path, label: path, program: "/bin/x", arguments: [],
                        runAtLoad: true, keepAlive: false, plistSHA256: sha)
        }
        let diff = StartupDiff.between(old: [item("/a", "1"), item("/b", "2")],
                                       new: [item("/b", "3"), item("/c", "4")])
        XCTAssertEqual(diff.added.map(\.plistPath), ["/c"])
        XCTAssertEqual(diff.changed.map(\.plistPath), ["/b"])
        XCTAssertEqual(diff.removed.map(\.plistPath), ["/a"])
        XCTAssertTrue(StartupDiff.between(old: [item("/a", "1")], new: [item("/a", "1")]).isEmpty)
    }

    func testUnsignedSuspiciousItemIsHighWithEvidence() throws {
        let item = try StartupItemParser.parse(plistAt: fixture("com.update.helper.plist"))
        let finding = FindingBuilder.finding(forNewStartupItem: item, signature: SignatureInfo(isSigned: false))
        XCTAssertEqual(finding.severity, .high)
        XCTAssertEqual(finding.title, "Unsigned startup item")
        XCTAssertEqual(finding.evidence.ruleID, "OS-STARTUP-0004")
        XCTAssertEqual(finding.evidence.sha256, item.plistSHA256)
        XCTAssertTrue(finding.summary.contains("every time you log in"))
        XCTAssertTrue(finding.recommendation.hasPrefix("Recommended: Quarantine"))
    }

    func testSignedNormalItemIsLowAndRecommendsReview() {
        let item = StartupItem(plistPath: "/Library/LaunchAgents/com.dropbox.plist", label: "com.dropbox.agent",
                               program: "/Applications/Dropbox.app/Contents/MacOS/Dropbox", arguments: [],
                               runAtLoad: true, keepAlive: false, plistSHA256: "x")
        let finding = FindingBuilder.finding(forNewStartupItem: item,
                                             signature: SignatureInfo(isSigned: true, authority: "Developer ID Application: Dropbox, Inc.",
                                                                      teamID: "G7HH3F8CAK", notarized: true))
        XCTAssertEqual(finding.severity, .low)
        XCTAssertEqual(finding.evidence.teamID, "G7HH3F8CAK")
        XCTAssertTrue(finding.recommendation.contains("Review"))
    }
}
