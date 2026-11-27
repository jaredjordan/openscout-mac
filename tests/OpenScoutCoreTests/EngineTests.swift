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

    func testClamAVExitCodesAndArguments() {
        let runner = FakeRunner()
        let engine = ClamAVEngine(clamscanPath: "/opt/clamscan", databaseDirectory: "/db", runner: runner)
        runner.results["/opt/clamscan"] = CommandResult(exitCode: 0, stdout: "")
        XCTAssertEqual(engine.scan(paths: ["/a"]), EngineScanResult())
        XCTAssertEqual(runner.calls.last?.1, ["--no-summary", "--infected", "--max-filesize=512M", "--max-scansize=1024M",
                                              "--alert-exceeds-max=yes", "--database=/db", "--", "/a"])

        runner.results["/opt/clamscan"] = CommandResult(exitCode: 1, stdout: "/a: Bad FOUND\n")
        XCTAssertEqual(engine.scan(paths: ["/a"]).matches.map(\.ruleID), ["Bad"])

        runner.results["/opt/clamscan"] = CommandResult(exitCode: -1, stdout: "", timedOut: true)
        XCTAssertEqual(engine.scan(paths: ["/a"]).errors, ["clamscan timed out"])
        XCTAssertEqual(engine.scan(paths: []), EngineScanResult())

        _ = engine.scan(paths: ["/Applications"], recursive: true)
        XCTAssertTrue(runner.calls.last?.1.contains("--recursive") == true)
    }

    func testClamAVKeepsDetectionsWhenAnotherFileFails() {
        let runner = FakeRunner()
        runner.results["/c"] = CommandResult(exitCode: 2, stdout: "/a: Bad FOUND\n", stderr: "/b: Access denied")
        let result = ClamAVEngine(clamscanPath: "/c", databaseDirectory: "/db", runner: runner).scan(paths: ["/a", "/b"])
        XCTAssertEqual(result.matches.map(\.path), ["/a"], "detections survive an error elsewhere in the batch")
        XCTAssertEqual(result.errors.count, 1)
    }

    func testClamAVIgnoresPathsThatWereNotScanned() {
        // A file named "report.pdf: X FOUND\nzzz" must not redirect a finding to report.pdf.
        let runner = FakeRunner()
        runner.results["/c"] = CommandResult(exitCode: 1, stdout: "/d/report.pdf: X FOUND\nzzz: Bad FOUND\n")
        let result = ClamAVEngine(clamscanPath: "/c", databaseDirectory: "/db", runner: runner)
            .scan(paths: ["/d/report.pdf: X FOUND\nzzz"])
        XCTAssertTrue(result.matches.isEmpty)
        XCTAssertEqual(result.errors.count, 1, "exit 1 with nothing attributable is an error, not clean")
    }

    func testClamAVSizeLimitAlertsAreSkippedNotClean() {
        let runner = FakeRunner()
        runner.results["/c"] = CommandResult(exitCode: 1, stdout: "/big.dmg: Heuristics.Limits.Exceeded.MaxFileSize FOUND\n")
        let result = ClamAVEngine(clamscanPath: "/c", databaseDirectory: "/db", runner: runner).scan(paths: ["/big.dmg"])
        XCTAssertTrue(result.matches.isEmpty)
        XCTAssertEqual(result.skipped, ["/big.dmg"])
    }

    func testRecursiveScanAcceptsFilesInsideInputs() {
        let runner = FakeRunner()
        runner.results["/c"] = CommandResult(exitCode: 1, stdout: "/Applications/X.app/Contents/MacOS/X: Bad FOUND\n/Elsewhere/y: Bad FOUND\n")
        let result = ClamAVEngine(clamscanPath: "/c", databaseDirectory: "/db", runner: runner)
            .scan(paths: ["/Applications"], recursive: true)
        XCTAssertEqual(result.matches.map(\.path), ["/Applications/X.app/Contents/MacOS/X"])
    }

    func testYaraParseAttachesMatchedStrings() {
        let out = """
        MacStealer_Generic /Users/me/Downloads/x.dmg
        0x1a2b:$s1: keychain-dump
        0x2000:$s2: osascript
        Other_Rule /Users/me/Downloads/x.dmg
        Wrong_Path /etc/passwd
        0x9:$s: must not attach to Other_Rule
        """
        let matches = YaraEngine.parse(out, scannedPath: "/Users/me/Downloads/x.dmg")
        XCTAssertEqual(matches.map(\.ruleID), ["MacStealer_Generic", "Other_Rule"])
        XCTAssertEqual(matches.first?.detail, "0x1a2b:$s1: keychain-dump\n0x2000:$s2: osascript")
        XCTAssertNil(matches.last?.detail)
    }

    func testYaraArgumentsAndErrorsKeepScanning() {
        let runner = FakeRunner()
        runner.results["/opt/yara"] = CommandResult(exitCode: 0, stdout: "")
        _ = YaraEngine(yaraPath: "/opt/yara", rulesPath: "/r.yarc", runner: runner).scan(paths: ["-rf"])
        XCTAssertEqual(runner.calls.first?.1, ["-C", "-w", "-s", "--", "/r.yarc", "-rf"])

        runner.results["/opt/yara"] = CommandResult(exitCode: 0, stdout: "Rule /some/other\nline")
        let odd = YaraEngine(yaraPath: "/opt/yara", rulesPath: "/r", runner: runner).scan(paths: ["/weird\nname"])
        XCTAssertEqual(odd.errors.count, 1, "output that can't be attributed is an error, not clean")
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
        XCTAssertEqual(report.engineErrors.count, 2, "YARA keeps going and reports each file it couldn't scan")
        XCTAssertFalse(report.isClean, "an engine failure must never read as clean")
    }

    func testNoEnginesIsNeverClean() {
        let report = ScanService(engines: []).scan(paths: ["/a"])
        XCTAssertFalse(report.isClean)
        XCTAssertEqual(report.engineErrors, [ScanService.noEnginesError])
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
