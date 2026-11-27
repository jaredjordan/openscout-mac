import Foundation
import XCTest
@testable import OpenScoutCore

final class SystemCheckTests: XCTestCase {
    func testCodesignParsing() {
        let signed = """
        Executable=/Applications/Plexamp.app/Contents/MacOS/Plexamp
        Identifier=tv.plex.plexamp
        Authority=Developer ID Application: Plex, Inc. (K4QJ56KR4A)
        Authority=Developer ID Certification Authority
        Authority=Apple Root CA
        TeamIdentifier=K4QJ56KR4A
        """
        let info = SignatureChecker.parseCodesign(exitCode: 0, output: signed)
        XCTAssertTrue(info.isSigned)
        XCTAssertEqual(info.authority, "Developer ID Application: Plex, Inc. (K4QJ56KR4A)")
        XCTAssertEqual(info.teamID, "K4QJ56KR4A")

        let adhoc = SignatureChecker.parseCodesign(exitCode: 0, output: "Signature=adhoc\nTeamIdentifier=not set")
        XCTAssertTrue(adhoc.isSigned)
        XCTAssertNil(adhoc.teamID)

        XCTAssertFalse(SignatureChecker.parseCodesign(exitCode: 1, output: "/tmp/x: code object is not signed at all").isSigned)
    }

    func testCheckerSkipsNotarizationForUnsigned() {
        let runner = FakeRunner()
        runner.results["/usr/bin/codesign"] = CommandResult(exitCode: 1, stdout: "", stderr: "code object is not signed at all")
        let info = SignatureChecker(runner: runner).check(path: "/tmp/x")
        XCTAssertFalse(info.isSigned)
        XCTAssertEqual(info.notarized, false)
        XCTAssertEqual(runner.calls.count, 1)
    }

    func testNotarizationParsing() {
        XCTAssertTrue(SignatureChecker.parseNotarized("/A.app: accepted\nsource=Notarized Developer ID"))
        XCTAssertFalse(SignatureChecker.parseNotarized("/A.app: accepted\nsource=Developer ID"))
        XCTAssertFalse(SignatureChecker.parseNotarized("/A.app: rejected"))
    }

    func testPostureParsing() {
        XCTAssertEqual(PostureChecker.parseGatekeeper(CommandResult(exitCode: 0, stdout: "assessments enabled")), true)
        XCTAssertEqual(PostureChecker.parseGatekeeper(CommandResult(exitCode: 0, stdout: "assessments disabled")), false)
        XCTAssertEqual(PostureChecker.parseSIP(CommandResult(exitCode: 0, stdout: "System Integrity Protection status: enabled.")), true)
        XCTAssertEqual(PostureChecker.parseSIP(CommandResult(exitCode: 0, stdout: "System Integrity Protection status: disabled.")), false)
        XCTAssertEqual(PostureChecker.parseFileVault(CommandResult(exitCode: 0, stdout: "FileVault is On.")), true)
        XCTAssertEqual(PostureChecker.parseFileVault(CommandResult(exitCode: 0, stdout: "FileVault is Off.")), false)
        XCTAssertEqual(PostureChecker.parseFirewall(CommandResult(exitCode: 0, stdout: "Firewall is enabled. (State = 1)")), true)
        XCTAssertEqual(PostureChecker.parseFirewall(CommandResult(exitCode: 0, stdout: "Firewall is disabled. (State = 0)")), false)
        XCTAssertNil(PostureChecker.parseSIP(CommandResult(exitCode: 127, stdout: "")), "missing tool reads as unknown, never on")
        XCTAssertNil(PostureChecker.parseSIP(CommandResult(exitCode: -1, stdout: "", timedOut: true)))
    }

    func testFullDiskAccessProbe() throws {
        let home = try makeTempDir()
        XCTAssertNil(FullDiskAccessProbe.hasAccess(home: home), "no probe folders means unknown")
        try FileManager.default.createDirectory(at: home.appendingPathComponent("Library/Mail"),
                                                withIntermediateDirectories: true)
        XCTAssertEqual(FullDiskAccessProbe.hasAccess(home: home), true)
    }

    func testChangeLogParsing() throws {
        let text = try String(contentsOf: fixture("CHANGELOG-sample.md"), encoding: .utf8)
        let releases = ChangeLogParser.parse(text)
        XCTAssertEqual(releases.map(\.version), ["Unreleased", "0.1.0"])
        XCTAssertEqual(releases[1].date, "2026-11-27")
        XCTAssertEqual(releases[1].sections["Added"], ["Startup item watcher.", "Quarantine with restore."])
        XCTAssertEqual(releases[1].sections["Removed"]?.count, 1, "removed detections must appear in the log")
    }
}
