import Foundation
import XCTest
@testable import OpenScoutCore

final class QuarantineTests: XCTestCase {
    var root: URL!
    var work: URL!
    let fm = FileManager.default

    override func setUpWithError() throws {
        root = try makeTempDir().appendingPathComponent("quarantine")
        work = try makeTempDir()
    }

    func perms(_ url: URL) throws -> Int {
        (try fm.attributesOfItem(atPath: url.path)[.posixPermissions] as! NSNumber).intValue
    }

    func testRoundTripRestoresBytesAndPermissions() throws {
        let file = work.appendingPathComponent("helper")
        try Data("payload bytes".utf8).write(to: file)
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: file.path)
        let store = try QuarantineStore(root: root)

        let record = try store.quarantine(fileAt: file, finding: sampleFinding(path: file.path))
        XCTAssertFalse(fm.fileExists(atPath: file.path))
        XCTAssertEqual(try perms(root), 0o700)
        let payload = root.appendingPathComponent(record.id.uuidString).appendingPathComponent("payload")
        XCTAssertEqual(try perms(payload), 0o400, "quarantined files must not be executable")
        XCTAssertEqual(store.records().map(\.id), [record.id])
        XCTAssertEqual(store.records().first?.finding.evidence.ruleID, "TEST-1")

        try store.restore(id: record.id)
        XCTAssertEqual(try Data(contentsOf: file), Data("payload bytes".utf8))
        XCTAssertEqual(try perms(file), 0o755)
        XCTAssertTrue(store.records().isEmpty)
    }

    func testRefusesSymlinks() throws {
        let target = work.appendingPathComponent("real")
        try Data("x".utf8).write(to: target)
        let link = work.appendingPathComponent("link")
        try fm.createSymbolicLink(at: link, withDestinationURL: target)
        let store = try QuarantineStore(root: root)
        XCTAssertThrowsError(try store.quarantine(fileAt: link, finding: sampleFinding())) {
            XCTAssertEqual($0 as? QuarantineError, .notARegularFile(link.path))
        }
        XCTAssertTrue(fm.fileExists(atPath: target.path))
    }

    func testRestoreNeverOverwrites() throws {
        let file = work.appendingPathComponent("app")
        try Data("old".utf8).write(to: file)
        let store = try QuarantineStore(root: root)
        let record = try store.quarantine(fileAt: file, finding: sampleFinding())
        try Data("new".utf8).write(to: file)
        XCTAssertThrowsError(try store.restore(id: record.id)) {
            XCTAssertEqual($0 as? QuarantineError, .destinationOccupied(file.path))
        }
        XCTAssertEqual(try Data(contentsOf: file), Data("new".utf8))
    }

    func testRestoreRefusesTamperedPayload() throws {
        let file = work.appendingPathComponent("app")
        try Data("original".utf8).write(to: file)
        let store = try QuarantineStore(root: root)
        let record = try store.quarantine(fileAt: file, finding: sampleFinding())
        let payload = root.appendingPathComponent(record.id.uuidString).appendingPathComponent("payload")
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: payload.path)
        try Data("swapped".utf8).write(to: payload)
        XCTAssertThrowsError(try store.restore(id: record.id)) {
            XCTAssertEqual($0 as? QuarantineError, .payloadChanged(record.id))
        }
        XCTAssertFalse(fm.fileExists(atPath: file.path))
    }

    func testMissingSourceAndRecord() throws {
        let store = try QuarantineStore(root: root)
        let missing = work.appendingPathComponent("nope")
        XCTAssertThrowsError(try store.quarantine(fileAt: missing, finding: sampleFinding())) {
            XCTAssertEqual($0 as? QuarantineError, .sourceMissing(missing.path))
        }
        let id = UUID()
        XCTAssertThrowsError(try store.restore(id: id)) {
            XCTAssertEqual($0 as? QuarantineError, .recordMissing(id))
        }
    }
}
