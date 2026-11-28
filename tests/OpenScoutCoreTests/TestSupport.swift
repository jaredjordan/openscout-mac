import Foundation
import XCTest
@testable import OpenScoutCore

/// A command runner that returns canned results and records what it was asked to run.
final class FakeRunner: CommandRunner, @unchecked Sendable {
    var results: [String: CommandResult] = [:]
    var calls: [(String, [String])] = []
    private let lock = NSLock()

    func run(_ executable: String, _ arguments: [String], timeout: TimeInterval) -> CommandResult {
        lock.lock(); defer { lock.unlock() }
        calls.append((executable, arguments))
        return results[executable] ?? CommandResult(exitCode: 127, stdout: "", stderr: "missing")
    }
}

func makeTempDir(_ name: String = #function) throws -> URL {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("openscout-tests-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

func fixture(_ name: String) -> URL {
    Bundle.module.url(forResource: "Fixtures/\(name)", withExtension: nil)
        ?? Bundle.module.resourceURL!.appendingPathComponent("Fixtures").appendingPathComponent(name)
}

func sampleFinding(path: String = "/tmp/x") -> Finding {
    Finding(title: "Test", summary: "A test finding.", recommendation: "Recommended: Quarantine.",
            severity: .high, evidence: Evidence(path: path, engine: .yara, ruleID: "TEST-1"))
}

func utcCalendar() -> Calendar {
    var calendar = Calendar(identifier: .gregorian)
    calendar.timeZone = TimeZone(identifier: "UTC")!
    return calendar
}

func date(_ iso: String) -> Date {
    let formatter = ISO8601DateFormatter()
    return formatter.date(from: iso)!
}
