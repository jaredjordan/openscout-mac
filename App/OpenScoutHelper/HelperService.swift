import Foundation
import OpenScoutCore
import OpenScoutMac

/// The background helper. Watches, scans, quarantines and keeps definitions current.
/// The app is only a window onto this process.
final class HelperService: NSObject, OpenScoutHelperProtocol, @unchecked Sendable {
    let store = StateStore()
    let allowStore = AllowStore(fileURL: Paths.allowList)
    let definitions = DefinitionStore(root: Paths.definitions)
    let quarantineStore: QuarantineStore
    let signatures = SignatureChecker()
    let posture = PostureChecker()

    private var startupWatcher: FileWatcher?
    private var downloadsWatcher: FileWatcher?
    private var timer: DispatchSourceTimer?
    private let work = DispatchQueue(label: "openscout.work", qos: .utility)
    private let control = NSLock()
    private var scanProgress: Double?
    private var scanPaused = false
    private var scanCancelled = false
    private var lastPosture: [PostureResult] = []

    override init() {
        try? Paths.ensure()
        // If the quarantine folder can't be created, fail loudly: quarantining is the core promise.
        quarantineStore = try! QuarantineStore(root: Paths.quarantine)
        super.init()
    }

    // MARK: Lifecycle

    func start() {
        Notifier.registerCategories()
        let startupDirs = StartupLocations.standard(home: Paths.home)
        store.update { state in
            if state.startupBaseline.isEmpty {
                state.startupBaseline = StartupItemScanner.scan(directories: startupDirs).items
            }
        }
        startupWatcher = FileWatcher(paths: startupDirs.map(\.path)) { [weak self] _ in
            self?.work.async { self?.checkStartupItems() }
        }
        startupWatcher?.start()
        downloadsWatcher = FileWatcher(paths: [Paths.downloads.path]) { [weak self] changed in
            self?.work.async { self?.scanNewDownloads(changed) }
        }
        downloadsWatcher?.start()

        let timer = DispatchSource.makeTimerSource(queue: work)
        timer.schedule(deadline: .now() + 30, repeating: 15 * 60)
        timer.setEventHandler { [weak self] in self?.tick() }
        timer.resume()
        self.timer = timer
        work.async { [weak self] in self?.lastPosture = self?.posture.runAll() ?? [] }
    }

    /// Every 15 minutes: definitions, then scheduled scans.
    private func tick() {
        let now = Date()
        let conditions = SystemConditions.current()
        let (lastCheck, lastQuick, lastFull, settings) = store.read {
            ($0.lastClamAVCheck, $0.lastQuickScan, $0.lastFullScan, $0.settings)
        }
        if UpdatePolicy.shouldCheckClamAV(lastCheck: lastCheck, now: now) {
            _ = refreshClamAV()
        }
        if ScanPlanner.quickScanDue(lastQuickScan: lastQuick, now: now, settings: settings) {
            runScan(.quick, userStarted: false)
        } else if ScanPlanner.fullScanDue(lastFullScan: lastFull, now: now, settings: settings, conditions: conditions) {
            runScan(.full, userStarted: false)
        }
        lastPosture = posture.runAll()
    }

    // MARK: Startup items

    private func checkStartupItems() {
        let scan = StartupItemScanner.scan(directories: StartupLocations.standard(home: Paths.home))
        let baseline = store.read(\.startupBaseline)
        let diff = StartupDiff.between(old: baseline, new: scan.items)
        for item in diff.added + diff.changed {
            if allowStore.isAllowed(path: item.plistPath, sha256: item.plistSHA256) { continue }
            let signature = item.program.map { signatures.check(path: $0) }
            let finding = FindingBuilder.finding(forNewStartupItem: item, signature: signature)
            record(finding)
        }
        for path in scan.unreadable {
            store.log("Couldn't read startup item \(path)")
        }
        store.update { $0.startupBaseline = scan.items }
    }

    // MARK: Scanning

    private func scanService() -> ScanService {
        var engines: [ScanEngine] = []
        if let clam = Paths.tool("clamscan"),
           FileManager.default.fileExists(atPath: definitions.currentDirectory(source: "clamav").path) {
            engines.append(ClamAVEngine(clamscanPath: clam,
                                        databaseDirectory: definitions.currentDirectory(source: "clamav").path))
        }
        let rules = definitions.currentDirectory(source: "yara").appendingPathComponent("rules.yarc")
        if let yara = Paths.tool("yara"), FileManager.default.fileExists(atPath: rules.path) {
            engines.append(YaraEngine(yaraPath: yara, rulesPath: rules.path))
        }
        let version = definitions.currentManifest(source: "clamav")?.version
        return ScanService(engines: engines, allowStore: allowStore, definitionsVersion: version)
    }

    private func scanNewDownloads(_ paths: [String]) {
        let files = paths.filter { path in
            var isDir: ObjCBool = false
            return FileManager.default.fileExists(atPath: path, isDirectory: &isDir) && !isDir.boolValue
                && !ScanTargets.isPartialDownload(path)
        }
        guard !files.isEmpty else { return }
        let report = scanService().scan(paths: files)
        report.findings.forEach(record)
        report.engineErrors.forEach { store.log("Scan problem: \($0)") }
        if report.findings.isEmpty {
            for file in files { store.log("\(URL(fileURLWithPath: file).lastPathComponent) in Downloads, clean") }
        }
    }

    private func runScan(_ kind: ScanKind, userStarted: Bool) {
        control.lock()
        if scanProgress != nil { control.unlock(); return }
        scanProgress = 0
        scanPaused = false
        scanCancelled = false
        control.unlock()

        let roots: [URL] = kind == .quick
            ? ScanTargets.quickScanRoots(home: Paths.home)
            : [Paths.home, URL(fileURLWithPath: "/Applications"), URL(fileURLWithPath: "/Library"),
               URL(fileURLWithPath: "/Users/Shared")]
        let files = enumerateFiles(roots: roots)
        let service = scanService()
        var findings = 0
        var problems = 0
        let batch = 200
        var index = 0
        while index < files.count {
            if isCancelled() { break }
            if kind == .full && ScanPlanner.shouldPauseFullScan(conditions: SystemConditions.current()) && !userStarted {
                setPaused(true)
                Thread.sleep(forTimeInterval: 30)
                continue
            }
            setPaused(false)
            let slice = Array(files[index..<min(index + batch, files.count)])
            let report = service.scan(paths: slice)
            report.findings.forEach(record)
            findings += report.findings.count
            problems += report.engineErrors.count
            index += slice.count
            setProgress(Double(index) / Double(max(files.count, 1)))
        }
        let cancelled = isCancelled()
        control.lock(); scanProgress = nil; scanPaused = false; control.unlock()
        let name = kind == .quick ? "Quick scan" : "Full scan"
        store.update { state in
            if !cancelled {
                if kind == .quick { state.lastQuickScan = Date() } else { state.lastFullScan = Date() }
            }
            let outcome = cancelled ? "stopped" : (findings == 0 ? "nothing found" : "\(findings) found")
            let suffix = problems > 0 ? ", \(problems) engine problems" : ""
            state.activity.append(ActivityEntry(text: "\(name), \(outcome)\(suffix)"))
        }
    }

    private func enumerateFiles(roots: [URL]) -> [String] {
        var files: [String] = []
        let skip = [Paths.support.path, "/Library/Caches", Paths.home.appendingPathComponent("Library/Caches").path]
        for root in roots {
            guard let walker = FileManager.default.enumerator(
                at: root, includingPropertiesForKeys: [.isRegularFileKey],
                options: [.skipsPackageDescendants], errorHandler: { _, _ in true }) else { continue }
            for case let url as URL in walker {
                if skip.contains(where: { url.path.hasPrefix($0) }) { walker.skipDescendants(); continue }
                if (try? url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true {
                    files.append(url.path)
                }
            }
        }
        return files
    }

    private func record(_ finding: Finding) {
        var isNew = false
        store.update { state in
            let duplicate = state.findings.contains {
                $0.evidence.path == finding.evidence.path && $0.evidence.ruleID == finding.evidence.ruleID
            }
            if !duplicate {
                state.findings.append(finding)
                state.activity.append(ActivityEntry(text: "Found: \(finding.title)"))
                isNew = true
            }
        }
        if isNew && finding.severity >= .medium { Notifier.post(finding) }
    }

    private func setProgress(_ value: Double) { control.lock(); scanProgress = value; control.unlock() }
    private func setPaused(_ value: Bool) { control.lock(); scanPaused = value; control.unlock() }
    private func isCancelled() -> Bool { control.lock(); defer { control.unlock() }; return scanCancelled }

    // MARK: Definitions

    /// Runs ClamAV's own updater into a staging folder, then installs through the five-step store.
    @discardableResult
    private func refreshClamAV() -> String? {
        store.update { $0.lastClamAVCheck = Date() }
        guard let freshclam = Paths.tool("freshclam"), let clamscan = Paths.tool("clamscan") else {
            return "ClamAV isn't installed. Install it with: brew install clamav"
        }
        let download = Paths.support.appendingPathComponent("Downloads-clamav", isDirectory: true)
        try? FileManager.default.removeItem(at: download)
        try? FileManager.default.createDirectory(at: download, withIntermediateDirectories: true)
        let result = ProcessCommandRunner().run(freshclam, ["--datadir=\(download.path)", "--stdout", "--no-warnings"],
                                                timeout: 900)
        guard result.exitCode == 0 else { return "ClamAV update failed: \(result.stderr.prefix(300))" }
        do {
            let names = try FileManager.default.contentsOfDirectory(atPath: download.path)
                .filter { $0.hasSuffix(".cvd") || $0.hasSuffix(".cld") }
            for extra in try FileManager.default.contentsOfDirectory(atPath: download.path) where !names.contains(extra) {
                try FileManager.default.removeItem(at: download.appendingPathComponent(extra))
            }
            var files: [String: String] = [:]
            for name in names { files[name] = try Hashing.sha256(fileAt: download.appendingPathComponent(name)) }
            let version = ISO8601DateFormatter().string(from: Date())
            let corpus = ["/Applications"]
            let currentDB = definitions.currentDirectory(source: "clamav")
            let currentlyFlagged: Set<String> = FileManager.default.fileExists(atPath: currentDB.path)
                ? Set((try? ClamAVEngine(clamscanPath: clamscan, databaseDirectory: currentDB.path).scan(paths: corpus))?.map(\.path) ?? [])
                : []
            try definitions.install(manifest: DefinitionManifest(source: "clamav", version: version, files: files),
                                    from: download, currentlyFlagged: currentlyFlagged) { staged in
                Set(try ClamAVEngine(clamscanPath: clamscan, databaseDirectory: staged.path).scan(paths: corpus).map(\.path))
            }
            store.update {
                $0.lastDefinitionsUpdate = Date()
                $0.activity.append(ActivityEntry(text: "Definitions updated (ClamAV \(version))"))
            }
            return nil
        } catch DefinitionError.corpusCheckFailed(let flagged) {
            store.log("Held a ClamAV update: it flagged \(flagged.count) installed apps it didn't flag before")
            return "Update held for review"
        } catch {
            return "ClamAV update failed: \(error)"
        }
    }

    // MARK: XPC

    private func currentStatus() -> HelperStatus {
        control.lock()
        let progress = scanProgress
        let paused = scanPaused
        control.unlock()
        let fda = FullDiskAccessProbe.hasAccess(home: Paths.home)
        return store.read { state in
            let inputs = ProtectionInputs(fullDiskAccess: fda, helperRunning: true, openFindings: state.findings.count,
                                          scanProgress: progress, lastDefinitionsUpdate: state.lastDefinitionsUpdate)
            let mark = ProtectionState.mark(for: inputs, now: Date())
            return HelperStatus(mark: mark,
                                accessibilityLabel: ProtectionState.accessibilityLabel(for: mark, inputs: inputs),
                                fullDiskAccess: fda, lastQuickScan: state.lastQuickScan, lastFullScan: state.lastFullScan,
                                lastDefinitionsUpdate: state.lastDefinitionsUpdate,
                                definitionsVersion: definitions.currentManifest(source: "clamav")?.version,
                                scanProgress: progress, scanPaused: paused, findings: state.findings,
                                startupItems: state.startupBaseline, posture: lastPosture,
                                recentActivity: Array(state.activity.suffix(20).reversed()),
                                settings: state.settings)
        }
    }

    func status(reply: @escaping (Data?, String?) -> Void) {
        reply(try? StateStore.encoder.encode(currentStatus()), nil)
    }

    func startScan(kind: String, reply: @escaping (String?) -> Void) {
        guard let scanKind = ScanKind(rawValue: kind) else { return reply("Unknown scan kind") }
        work.async { [weak self] in self?.runScan(scanKind, userStarted: true) }
        reply(nil)
    }

    func pauseScan(reply: @escaping (String?) -> Void) { setPaused(true); reply(nil) }
    func resumeScan(reply: @escaping (String?) -> Void) { setPaused(false); reply(nil) }

    func stopScan(reply: @escaping (String?) -> Void) {
        control.lock(); scanCancelled = true; control.unlock()
        reply(nil)
    }

    func quarantine(findingID: String, reply: @escaping (String?) -> Void) {
        guard let id = UUID(uuidString: findingID),
              let finding = store.read({ $0.findings.first { $0.id == id } }) else {
            return reply("That finding no longer exists")
        }
        do {
            try quarantineStore.quarantine(fileAt: URL(fileURLWithPath: finding.evidence.path), finding: finding)
            store.update {
                $0.findings.removeAll { $0.id == id }
                $0.activity.append(ActivityEntry(text: "Quarantined \(URL(fileURLWithPath: finding.evidence.path).lastPathComponent)"))
            }
            reply(nil)
        } catch {
            reply("Couldn't quarantine: \(error)")
        }
    }

    func allow(findingID: String, confirmed: Bool, reply: @escaping (String?) -> Void) {
        guard confirmed else { return reply("Allow needs confirmation") }
        guard let id = UUID(uuidString: findingID),
              let finding = store.read({ $0.findings.first { $0.id == id } }),
              let sha = finding.evidence.sha256 ?? (try? Hashing.sha256(fileAt: URL(fileURLWithPath: finding.evidence.path))) else {
            return reply("That finding no longer exists")
        }
        do {
            try allowStore.allow(AllowEntry(path: finding.evidence.path, sha256: sha,
                                            reason: "Allowed by you from \(finding.evidence.ruleID)"))
            store.update {
                $0.findings.removeAll { $0.id == id }
                $0.activity.append(ActivityEntry(text: "Allowed \(URL(fileURLWithPath: finding.evidence.path).lastPathComponent)"))
            }
            reply(nil)
        } catch {
            reply("Couldn't save: \(error)")
        }
    }

    func quarantineRecords(reply: @escaping (Data?, String?) -> Void) {
        reply(try? StateStore.encoder.encode(quarantineStore.records()), nil)
    }

    func restore(recordID: String, reply: @escaping (String?) -> Void) {
        guard let id = UUID(uuidString: recordID) else { return reply("Unknown item") }
        do {
            let record = try quarantineStore.restore(id: id)
            // Restoring allows these exact bytes, so the same file isn't flagged again.
            try allowStore.allow(AllowEntry(path: record.originalPath, sha256: record.sha256,
                                            reason: "Restored from quarantine"))
            store.log("Restored \(URL(fileURLWithPath: record.originalPath).lastPathComponent)")
            reply(nil)
        } catch {
            reply("Couldn't restore: \(error)")
        }
    }

    func updateSettings(_ data: Data, reply: @escaping (String?) -> Void) {
        guard let settings = try? StateStore.decoder.decode(ScanSettings.self, from: data),
              (0...23).contains(settings.quickScanHour), (0...23).contains(settings.fullScanHour),
              (1...7).contains(settings.fullScanWeekday) else {
            return reply("Those settings aren't valid")
        }
        store.update { $0.settings = settings }
        reply(nil)
    }

    func updateDefinitions(reply: @escaping (String?) -> Void) {
        work.async { [weak self] in reply(self?.refreshClamAV()) }
    }
}
