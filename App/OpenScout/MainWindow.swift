import OpenScoutCore
import SwiftUI

enum SidebarItem: String, CaseIterable, Identifiable {
    case overview = "Overview"
    case findings = "Findings"
    case startupItems = "Startup Items"
    case quarantine = "Quarantine"
    case changes = "Changes"

    var id: String { rawValue }

    var symbol: String {
        switch self {
        case .overview: return "gauge.with.dots.needle.33percent"
        case .findings: return "exclamationmark.shield"
        case .startupItems: return "power"
        case .quarantine: return "archivebox"
        case .changes: return "list.bullet.rectangle"
        }
    }
}

struct MainWindow: View {
    @EnvironmentObject var model: AppModel
    @State private var selection: SidebarItem? = .findings
    @State private var showInspector = true

    var body: some View {
        NavigationSplitView {
            List(SidebarItem.allCases, selection: $selection) { item in
                Label(item.rawValue, systemImage: item.symbol)
                    .badge(badge(for: item))
                    .tag(item)
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 200)
        } detail: {
            switch selection ?? .findings {
            case .overview: OverviewView()
            case .findings: FindingsView(showInspector: $showInspector)
            case .startupItems: StartupItemsView()
            case .quarantine: QuarantineView()
            case .changes: ChangesView()
            }
        }
        .toolbar {
            ToolbarItemGroup {
                Toggle(isOn: $model.hidePaths) {
                    Label("Hide Paths", systemImage: model.hidePaths ? "eye.slash" : "eye")
                }
                .help("Hide home-folder paths while screen sharing")
                Button { model.scanNow() } label: { Label("Scan Now", systemImage: "magnifyingglass") }
                    .disabled(model.mark == .scanning)
            }
        }
        .onChange(of: model.selectedFindingID) { _, id in
            if id != nil { selection = .findings }
        }
    }

    private func badge(for item: SidebarItem) -> Int {
        switch item {
        case .findings: return model.status?.findings.count ?? 0
        case .quarantine: return model.quarantine.count
        default: return 0
        }
    }
}

struct OverviewView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Form {
            Section("Protection") {
                LabeledContent("Status", value: model.mark.headline)
                LabeledContent("Full Disk Access", value: describe(model.status?.fullDiskAccess))
                LabeledContent("Last quick scan", value: describe(model.status?.lastQuickScan))
                LabeledContent("Last full scan", value: describe(model.status?.lastFullScan))
                LabeledContent("Definitions", value: model.status?.definitionsVersion ?? "Not downloaded yet")
            }
            Section("Watched live") {
                Text("Startup item folders")
                Text("Downloads")
            }
            Section("macOS protections") {
                ForEach(model.status?.posture ?? [], id: \.check) { result in
                    LabeledContent(title(result.check), value: describe(result.enabled))
                }
            }
            if let error = model.lastError {
                Section { Text(error).foregroundStyle(.secondary) }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Overview")
    }

    private func title(_ check: PostureCheckID) -> String {
        switch check {
        case .gatekeeper: return "Gatekeeper"
        case .sip: return "System Integrity Protection"
        case .fileVault: return "FileVault"
        case .firewall: return "Firewall"
        }
    }

    private func describe(_ value: Bool?) -> String {
        switch value {
        case .some(true): return "On"
        case .some(false): return "Off"
        case .none: return "Unknown"
        }
    }

    private func describe(_ date: Date?) -> String {
        date.map { $0.formatted(date: .abbreviated, time: .shortened) } ?? "Never"
    }
}

struct FindingsView: View {
    @EnvironmentObject var model: AppModel
    @Binding var showInspector: Bool

    var body: some View {
        let findings = model.status?.findings ?? []
        List(findings, selection: $model.selectedFindingID) { finding in
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(finding.title).font(.headline)
                    Spacer()
                    Text(finding.foundAt.formatted(date: .omitted, time: .shortened))
                        .foregroundStyle(.secondary)
                }
                Text(finding.summary).foregroundStyle(.secondary).lineLimit(2)
            }
            .padding(.vertical, 4)
            .tag(finding.id)
        }
        .overlay {
            if findings.isEmpty {
                ContentUnavailableView("Nothing needs review", systemImage: "checkmark.shield",
                                       description: Text("Nothing has been deleted. Quarantined files are in Quarantine."))
            }
        }
        .navigationTitle("Findings")
        .inspector(isPresented: $showInspector) {
            if let id = model.selectedFindingID, let finding = findings.first(where: { $0.id == id }) {
                FindingInspector(finding: finding)
            } else {
                ContentUnavailableView("Select a finding", systemImage: "sidebar.right")
            }
        }
    }
}

struct StartupItemsView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Table(model.status?.startupItems ?? []) {
            TableColumn("Label", value: \.label)
            TableColumn("Runs") { Text(model.display($0.program ?? "Unknown")) }
            TableColumn("At login") { Text($0.runAtLoad || $0.keepAlive ? "Yes" : "No") }
            TableColumn("Location") { item in
                Text(item.programInSuspiciousLocation ? "Temporary or hidden folder" : "Normal")
            }
        }
        .navigationTitle("Startup Items")
    }
}

extension StartupItem: Identifiable {
    public var id: String { plistPath }
}
