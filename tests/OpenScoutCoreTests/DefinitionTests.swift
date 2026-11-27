import Foundation
import XCTest
@testable import OpenScoutCore

final class DefinitionTests: XCTestCase {
    let fm = FileManager.default

    func makeDownload(_ files: [String: String]) throws -> (URL, [String: String]) {
        let dir = try makeTempDir()
        var hashes: [String: String] = [:]
        for (name, body) in files {
            let data = Data(body.utf8)
            try data.write(to: dir.appendingPathComponent(name))
            hashes[name] = Hashing.sha256(data: data)
        }
        return (dir, hashes)
    }

    func testInstallVerifiesSwapsAndKeepsPrevious() throws {
        let store = DefinitionStore(root: try makeTempDir())
        let (v1, h1) = try makeDownload(["daily.cvd": "one"])
        try store.install(manifest: DefinitionManifest(source: "clamav", version: "1", files: h1),
                          from: v1, corpusCheck: { _ in [] })
        XCTAssertEqual(store.currentManifest(source: "clamav")?.version, "1")

        let (v2, h2) = try makeDownload(["daily.cvd": "two"])
        try store.install(manifest: DefinitionManifest(source: "clamav", version: "2", files: h2),
                          from: v2, corpusCheck: { _ in [] })
        XCTAssertEqual(store.currentManifest(source: "clamav")?.version, "2")
        let current = store.currentDirectory(source: "clamav").appendingPathComponent("daily.cvd")
        XCTAssertEqual(try String(contentsOf: current, encoding: .utf8), "two")

        try store.rollback(source: "clamav")
        XCTAssertEqual(store.currentManifest(source: "clamav")?.version, "1")
    }

    func testHashMismatchNeverInstalls() throws {
        let store = DefinitionStore(root: try makeTempDir())
        let (dir, _) = try makeDownload(["rules.yarc": "tampered"])
        let manifest = DefinitionManifest(source: "yara", version: "9",
                                          files: ["rules.yarc": String(repeating: "0", count: 64)])
        XCTAssertThrowsError(try store.install(manifest: manifest, from: dir, corpusCheck: { _ in [] })) {
            guard case .hashMismatch(let file, _, _)? = $0 as? DefinitionError else {
                return XCTFail("expected hashMismatch, got \($0)")
            }
            XCTAssertEqual(file, "rules.yarc")
        }
        XCTAssertNil(store.currentManifest(source: "yara"))
    }

    func testUnexpectedAndMissingFilesAreRejected() throws {
        let store = DefinitionStore(root: try makeTempDir())
        let (dir, hashes) = try makeDownload(["a.cvd": "a", "extra.sh": "echo"])
        var listed = hashes
        listed.removeValue(forKey: "extra.sh")
        XCTAssertThrowsError(try store.install(manifest: DefinitionManifest(source: "clamav", version: "1", files: listed),
                                               from: dir, corpusCheck: { _ in [] })) {
            XCTAssertEqual($0 as? DefinitionError, .unexpectedFile("extra.sh"))
        }
        let (dir2, h2) = try makeDownload(["a.cvd": "a"])
        var withMissing = h2
        withMissing["b.cvd"] = String(repeating: "1", count: 64)
        XCTAssertThrowsError(try store.install(manifest: DefinitionManifest(source: "clamav", version: "1", files: withMissing),
                                               from: dir2, corpusCheck: { _ in [] })) {
            XCTAssertEqual($0 as? DefinitionError, .missingFile("b.cvd"))
        }
    }

    func testCorpusCheckHoldsUpdateThatFlagsNewCleanFiles() throws {
        let store = DefinitionStore(root: try makeTempDir())
        let (v1, h1) = try makeDownload(["daily.cvd": "one"])
        try store.install(manifest: DefinitionManifest(source: "clamav", version: "1", files: h1),
                          from: v1, corpusCheck: { _ in [] })
        let (v2, h2) = try makeDownload(["daily.cvd": "bad"])
        XCTAssertThrowsError(try store.install(
            manifest: DefinitionManifest(source: "clamav", version: "2", files: h2), from: v2,
            currentlyFlagged: ["/Applications/Old.app"],
            corpusCheck: { _ in ["/Applications/Old.app", "/Applications/Plexamp.app"] })) {
            XCTAssertEqual($0 as? DefinitionError, .corpusCheckFailed(newlyFlagged: ["/Applications/Plexamp.app"]))
        }
        XCTAssertEqual(store.currentManifest(source: "clamav")?.version, "1", "held update must not replace current")
    }

    func testUnsafeFileNamesRejected() {
        for bad in ["", ".", "..", "../x", "a/b", ".hidden", "manifest.json", "a\\b"] {
            XCTAssertFalse(DefinitionStore.isSafeFileName(bad), bad)
        }
        XCTAssertTrue(DefinitionStore.isSafeFileName("daily.cvd"))
    }

    func testRollbackWithNothingPrevious() throws {
        let store = DefinitionStore(root: try makeTempDir())
        XCTAssertThrowsError(try store.rollback(source: "clamav")) {
            XCTAssertEqual($0 as? DefinitionError, .nothingToRollBack)
        }
    }

    func testUpdatePolicy() {
        let now = date("2026-11-27T12:00:00Z")
        XCTAssertTrue(UpdatePolicy.shouldCheckClamAV(lastCheck: nil, now: now))
        XCTAssertFalse(UpdatePolicy.shouldCheckClamAV(lastCheck: now.addingTimeInterval(-30 * 60), now: now))
        XCTAssertFalse(UpdatePolicy.shouldCheckClamAV(lastCheck: now.addingTimeInterval(-3 * 3600), now: now))
        XCTAssertTrue(UpdatePolicy.shouldCheckClamAV(lastCheck: now.addingTimeInterval(-4 * 3600), now: now))
        XCTAssertFalse(UpdatePolicy.shouldCheckYARA(lastCheck: now.addingTimeInterval(-23 * 3600), now: now))
        XCTAssertTrue(UpdatePolicy.shouldCheckYARA(lastCheck: now.addingTimeInterval(-24 * 3600), now: now))
        XCTAssertFalse(UpdatePolicy.isStale(lastUpdate: now.addingTimeInterval(-2 * 86400), now: now))
        XCTAssertTrue(UpdatePolicy.isStale(lastUpdate: now.addingTimeInterval(-4 * 86400), now: now))
        XCTAssertTrue(UpdatePolicy.isStale(lastUpdate: nil, now: now))
    }
}
