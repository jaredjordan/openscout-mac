import Foundation
import OpenScoutCore
import OpenScoutMac
import SwiftUI

/// The app's view of the helper. Polls status every two seconds while open.
@MainActor
final class AppModel: ObservableObject {
    @Published var status: HelperStatus?
    @Published var quarantine: [QuarantineRecord] = []
    @Published var lastError: String?
    @Published var hidePaths = false
    @Published var selectedFindingID: Finding.ID?
    private var lastGoodStatus = Date.distantPast

    private var connection: NSXPCConnection?
    private var timer: Timer?
    private var started = false

    var mark: MarkState { status?.mark ?? .unprotected }

    func start() {
        guard !started else { return }
        started = true
        connect()
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
    }

    private func connect() {
        let connection = NSXPCConnection(machServiceName: HelperIdentity.machServiceName, options: [])
        connection.remoteObjectInterface = .openScoutHelper
        connection.invalidationHandler = { [weak self] in
            Task { @MainActor in self?.connection = nil }
        }
        connection.resume()
        self.connection = connection
    }

    private func helper() -> OpenScoutHelperProtocol? {
        if connection == nil { connect() }
        return connection?.remoteObjectProxyWithErrorHandler { [weak self] error in
            Task { @MainActor in
                // Drop the old status: a dead helper must never keep showing All clear.
                self?.status = nil
                self?.lastError = "The background helper isn't responding. \(error.localizedDescription)"
            }
        } as? OpenScoutHelperProtocol
    }

    func refresh() {
        if status != nil && Date().timeIntervalSince(lastGoodStatus) > 10 {
            status = nil
        }
        helper()?.status { [weak self] data, error in
            Task { @MainActor in
                guard let self else { return }
                if let data, let decoded = try? Self.makeDecoder().decode(HelperStatus.self, from: data) {
                    self.status = decoded
                    self.lastGoodStatus = Date()
                    self.lastError = nil
                }
                if let error { self.lastError = error }
            }
        }
        helper()?.quarantineRecords { [weak self] data, _ in
            Task { @MainActor in
                guard let self, let data else { return }
                self.quarantine = (try? Self.makeDecoder().decode([QuarantineRecord].self, from: data)) ?? []
            }
        }
    }

    nonisolated private func handle(_ error: String?) {
        Task { @MainActor in
            self.lastError = error
            self.refresh()
        }
    }

    func scanNow() { helper()?.startScan(kind: ScanKind.quick.rawValue) { [weak self] in self?.handle($0) } }
    func pause() { helper()?.pauseScan { [weak self] in self?.handle($0) } }
    func resume() { helper()?.resumeScan { [weak self] in self?.handle($0) } }
    func stop() { helper()?.stopScan { [weak self] in self?.handle($0) } }
    func updateDefinitions() { helper()?.updateDefinitions { [weak self] in self?.handle($0) } }

    func updateSettings(_ change: (inout ScanSettings) -> Void) {
        var settings = status?.settings ?? ScanSettings()
        change(&settings)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(settings) else { return }
        helper()?.updateSettings(data) { [weak self] in self?.handle($0) }
    }

    func quarantine(_ finding: Finding) {
        helper()?.quarantine(findingID: finding.id.uuidString) { [weak self] in self?.handle($0) }
    }

    /// Only call after the confirmation dialog.
    func allowConfirmed(_ finding: Finding) {
        helper()?.allow(findingID: finding.id.uuidString, confirmed: true) { [weak self] in self?.handle($0) }
    }

    func restore(_ record: QuarantineRecord) {
        helper()?.restore(recordID: record.id.uuidString) { [weak self] in self?.handle($0) }
    }

    func display(_ path: String) -> String {
        guard hidePaths else { return path }
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return path.replacingOccurrences(of: home, with: "~").split(separator: "/").last.map { "…/\($0)" } ?? path
    }

    nonisolated static func makeDecoder() -> JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }
}
