import Foundation
import XCTest
@testable import OpenScoutCore

final class EngineTests: XCTestCase {
    func testClamAVParse() {
        let out = """
        /Users/me/Downloads/x.dmg: Osx.Trojan.Agent-12345 FOUND
        /Users/me/Downloads/odd: name.pkg: Osx.Adware.Pirrit FOUND
        /Users/me/Downloads/ok.zip: OK
        garbage
        """
        let matches = ClamAVEngine.parse(out)
        XCTAssertEqual(matches.map(\.path), ["/Users/me/Downloads/x.dmg", "/Users/me/Downloads/odd: name.pkg"])
        XCTAssertEqual(matches.map(\.ruleID), ["Osx.Trojan.Agent-12345", "Osx.Adware.Pirrit"])
    }

    func testClamAVExitCodes() throws {
        let runner = FakeRunner()
        let engine = ClamAVEngine(clamscanPath: "/opt/clamscan", databaseDirectory: "/db", runner: runner)
        runner.results["/opt/clamscan"] = CommandResult(exitCode: 0, stdout: "")
        XCTAssertEqual(try engine.scan(paths: ["/a"]), [])
        XCTAssertEqual(runner.calls.last?.1, ["--no-summary", "--infected", "--database=/db", "--", "/a"])

        runner.results["/opt/clamscan"] = CommandResult(exitCode: 1, stdout: "/a: Bad FOUND\n")
        XCTAssertEqual(try engine.scan(paths: ["/a"]).map(\.ruleID), ["Bad"])

        runner.results["/opt/clamscan"] = CommandResult(exitCode: 2, stdout: "", stderr: "db error")
        XCTAssertThrowsError(try engine.scan(paths: ["/a"]))

        runner.results["/opt/clamscan"] = CommandResult(exitCode: -1, stdout: "", timedOut: true)
        XCTAssertThrowsError(try engine.scan(paths: ["/a"])) { XCTAssertEqual($0 as? EngineError, .timedOut("clamscan")) }
        XCTAssertEqual(try engine.scan(paths: []), [])
    }

    func testYaraParseAttachesMatchedStrings() {
        let out = """
        MacStealer_Generic /Users/me/Downloads/x.dmg
        0x1a2b:$s1: keychain-dump
        0x2000:$s2: osascript
        Other_Rule /Users/me/Downloads/x.dmg
        Wrong_Path /etc/passwd
        """
        let matches = YaraEngine.parse(out, scannedPath: "/Users/me/Downloads/x.dmg")
        XCTAssertEqual(matches.map(\.ruleID), ["MacStealer_Generic", "Other_Rule"])
        XCTAssertEqual(matches.first?.detail, "0x1a2b:$s1: keychain-dump\n0x2000:$s2: osascript")
        XCTAssertNil(matches.last?.detail)
    }

    func testYaraArgumentsEndOptionsBeforePaths() throws {
        let runner = FakeRunner()
        runner.results["/opt/yara"] = CommandResult(exitCode: 0, stdout: "")
        _ = try YaraEngine(yaraPath: "/opt/yara", rulesPath: "/r.yarc", runner: runner).scan(paths: ["-rf"])
        XCTAssertEqual(runner.calls.first?.1, ["-C", "-w", "-s", "--", "/r.yarc", "-rf"])
    }

    func testScanServiceSkipsAllowedFilesAndReportsEngineErrors() throws {
        let dir = try makeTempDir()
        let bad = dir.appendingPathComponent("bad.bin")
        let allowed = dir.appendingPathComponent("allowed.bin")
        try Data("bad".utf8).write(to: bad)
        try Data("allowed".utf8).write(to: allowed)

        let clam = FakeRunner()
        clam.results["/c"] = CommandResult(exitCode: 1, stdout: "\(bad.path): Bad FOUND\n\(allowed.path): Bad FOUND\n")
        let broken = FakeRunner()
        broken.results["/y"] = CommandResult(exitCode: 2, stdout: "", stderr: "could not open rules")

        let allowStore = AllowStore(fileURL: dir.appendingPathComponent("allow.json"))
        try allowStore.allow(AllowEntry(path: allowed.path, sha256: try Hashing.sha256(fileAt: allowed), reason: "mine"))

        let service = ScanService(engines: [ClamAVEngine(clamscanPath: "/c", databaseDirectory: "/db", runner: clam),
                                            YaraEngine(yaraPath: "/y", rulesPath: "/r", runner: broken)],
                                  allowStore: allowStore, definitionsVersion: "2026.11.27")
        let report = service.scan(paths: [bad.path, allowed.path])
        XCTAssertEqual(report.findings.map(\.evidence.path), [bad.path])
        XCTAssertEqual(report.findings.first?.evidence.definitionsVersion, "2026.11.27")
        XCTAssertEqual(report.findings.first?.evidence.sha256, Hashing.sha256(data: Data("bad".utf8)))
        XCTAssertEqual(report.engineErrors.count, 1)
        XCTAssertFalse(report.isClean, "an engine failure must never read as clean")
    }

    func testAllowStorePersistsAndMatchesExactBytesOnly() throws {
        let dir = try makeTempDir()
        let url = dir.appendingPathComponent("allow.json")
        let store = AllowStore(fileURL: url)
        try store.allow(AllowEntry(path: "/a", sha256: "abc", reason: "installed it"))
        let reloaded = AllowStore(fileURL: url)
        XCTAssertTrue(reloaded.isAllowed(path: "/a", sha256: "abc"))
        XCTAssertFalse(reloaded.isAllowed(path: "/a", sha256: "changed"))
        try reloaded.revoke(path: "/a")
        XCTAssertFalse(AllowStore(fileURL: url).isAllowed(path: "/a", sha256: "abc"))
    }

    func testPartialDownloadsSkipped() {
        XCTAssertTrue(ScanTargets.isPartialDownload("/d/file.dmg.crdownload"))
        XCTAssertTrue(ScanTargets.isPartialDownload("/d/file.zip.download"))
        XCTAssertFalse(ScanTargets.isPartialDownload("/d/file.dmg"))
    }

    func testHashing() {
        XCTAssertEqual(Hashing.sha256(data: Data("abc".utf8)),
                       "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }

    func testProcessRunnerRunsWithoutShellAndTimesOut() throws {
        #if os(macOS) || os(Linux)
        let runner = ProcessCommandRunner()
        let echo = runner.run("/bin/echo", ["$(whoami)"], timeout: 5)
        XCTAssertEqual(echo.exitCode, 0)
        XCTAssertEqual(echo.stdout.trimmingCharacters(in: .whitespacesAndNewlines), "$(whoami)",
                       "arguments must not be expanded by a shell")
        let slow = runner.run("/bin/sleep", ["5"], timeout: 0.5)
        XCTAssertTrue(slow.timedOut)
        XCTAssertEqual(runner.run("/no/such/tool", [], timeout: 1).exitCode, 127)
        #endif
    }
}
