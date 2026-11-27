import OpenScoutCore
import OpenScoutMac
import ServiceManagement
import SwiftUI

/// Every change, newest first, read from the same CHANGELOG.md the repository publishes.
struct ChangesView: View {
    private let releases: [ChangeLogRelease] = {
        guard let url = Bundle.main.url(forResource: "CHANGELOG", withExtension: "md"),
              let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        return ChangeLogParser.parse(text)
    }()

    var body: some View {
        List {
            ForEach(releases, id: \.version) { release in
                Section {
                    ForEach(release.sections.keys.sorted(), id: \.self) { name in
                        Text(name).font(.subheadline.bold())
                        ForEach(release.sections[name] ?? [], id: \.self) { line in
                            Text(line)
                        }
                    }
                } header: {
                    Text(release.date.map { "\(release.version), \($0)" } ?? release.version)
                }
            }
            Link("Full history on GitHub", destination: URL(string: "https://github.com/jaredjordan/openscout-mac/blob/main/CHANGELOG.md")!)
        }
        .navigationTitle("Changes")
    }
}

/// Three steps in one window with Back and Continue. Each system prompt is explained first.
struct FirstRunView: View {
    @EnvironmentObject var model: AppModel
    @Binding var finished: Bool
    @Environment(\.dismiss) private var dismiss
    @State private var step = 0
    @State private var helperError: String?
    @State private var scheduleFullScan = true

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Step \(step + 1) of 3").font(.caption).foregroundStyle(.secondary)
            switch step {
            case 0:
                Text("Watch in the background").font(.title2.bold())
                Text("OpenScout runs a small helper so protection continues when the window is closed. macOS will ask you to allow it in Login Items.")
                if let helperError { Text(helperError).foregroundStyle(.secondary) }
            case 1:
                Text("Turn on Full Disk Access").font(.title2.bold())
                Text("Malware hides in Mail, Messages and Safari downloads. macOS keeps those folders private until you allow access. Nothing leaves your Mac.")
                Text(model.status?.fullDiskAccess == true ? "Full Disk Access is on." : "Waiting for Full Disk Access…")
                    .foregroundStyle(.secondary)
            default:
                Text("Choose your first scan").font(.title2.bold())
                Text("A quick scan takes about two minutes and starts now.")
                Toggle("Also run a full scan every Sunday night, on power, pausing whenever you use the Mac", isOn: $scheduleFullScan)
            }
            Spacer()
            HStack {
                if step > 0 { Button("Back") { step -= 1 } }
                Spacer()
                if step == 1 && model.status?.fullDiskAccess != true {
                    Button("Skip for Now") { step = 2 }
                    Button("Open Privacy Settings…") { PrivacySettings.openFullDiskAccess() }
                        .keyboardShortcut(.defaultAction)
                } else {
                    Button(step == 2 ? "Start Quick Scan" : "Continue") { advance() }
                        .keyboardShortcut(.defaultAction)
                }
            }
        }
        .padding(24)
        .onChange(of: model.status?.fullDiskAccess) { _, granted in
            // Move on by itself once access is granted.
            if step == 1 && granted == true { step = 2 }
        }
    }

    private func advance() {
        switch step {
        case 0:
            do {
                try HelperRegistration.register()
                step = 1
            } catch {
                helperError = "macOS needs your approval in System Settings > General > Login Items."
                HelperRegistration.openLoginItemsSettings()
            }
        case 1:
            step = 2
        default:
            let enableFull = scheduleFullScan
            model.updateSettings { $0.fullScanEnabled = enableFull }
            model.scanNow()
            finished = true
            dismiss()
        }
    }
}

struct SettingsView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        let settings = model.status?.settings ?? ScanSettings()
        Form {
            Section("Scans") {
                Toggle("Full scan every Sunday night", isOn: binding(settings.fullScanEnabled) { $0.fullScanEnabled = $1 })
                Toggle("Allow full scans on battery", isOn: binding(settings.fullScanOnBattery) { $0.fullScanOnBattery = $1 })
                Toggle("Show progress in the menu bar for scans I start",
                       isOn: binding(settings.liveActivityEnabled) { $0.liveActivityEnabled = $1 })
            }
            Section("Privacy") {
                Text("OpenScout sends nothing about your files anywhere. Fingerprint lookups are planned as an opt-in setting.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 460)
    }

    private func binding(_ value: Bool, set: @escaping (inout ScanSettings, Bool) -> Void) -> Binding<Bool> {
        Binding(get: { value }, set: { newValue in model.updateSettings { set(&$0, newValue) } })
    }
}
