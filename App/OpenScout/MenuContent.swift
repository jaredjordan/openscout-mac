import OpenScoutCore
import OpenScoutMac
import SwiftUI

/// A real NSMenu: standard items, no per-row icons, one icon in the header only.
struct MenuContent: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        let status = model.status
        Text(model.mark.headline)

        switch model.mark {
        case .unprotected where status?.fullDiskAccess == false:
            Text("Full Disk Access is off, so Mail, Messages and Safari aren't scanned")
            Button("Turn On Full Disk Access…") { PrivacySettings.openFullDiskAccess() }
        case .unprotected where status == nil:
            Text("The background helper isn't running")
            Button("Set Up OpenScout…") { openWindow(id: "setup") }
        case .unprotected:
            ForEach(status?.problems ?? [], id: \.self) { Text($0) }
            if status?.problems?.isEmpty ?? true { Text("Protection is incomplete") }
            Button("Update Definitions") { model.updateDefinitions() }
        case .scanning:
            if let progress = status?.scanProgress {
                Text(status?.scanPaused == true ? "Paused while you work" : "\(Int(progress * 100))% scanned")
            }
            if status?.scanPaused == true {
                Button("Resume Scan") { model.resume() }
            } else {
                Button("Pause Scan") { model.pause() }
            }
            Button("Stop Scan") { model.stop() }
        case .review:
            Text("Nothing has been deleted")
            ForEach(status?.findings ?? []) { finding in
                Button(finding.title) {
                    model.selectedFindingID = finding.id
                    openWindow(id: "main")
                }
            }
        case .clear, .stale:
            if let last = status?.lastQuickScan {
                Text("Last scan \(last.formatted(date: .omitted, time: .shortened)), nothing found")
            }
            if let defs = status?.lastDefinitionsUpdate {
                Text("Definitions updated \(defs.formatted(.relative(presentation: .named)))")
            } else {
                Text("Definitions haven't been downloaded yet")
            }
        }

        Divider()
        if model.mark != .scanning {
            Button("Scan Now") { model.scanNow() }.keyboardShortcut("s")
        }
        if model.mark == .stale {
            Button("Update Definitions") { model.updateDefinitions() }
        }
        Menu("Recent Activity") {
            ForEach(status?.recentActivity ?? []) { entry in
                Text("\(entry.date.formatted(date: .abbreviated, time: .shortened))  \(entry.text)")
            }
        }
        Button("Quarantine (\(model.quarantine.count))") { openWindow(id: "main") }
        Divider()
        Button("Open OpenScout") { openWindow(id: "main") }.keyboardShortcut("o")
        SettingsLink { Text("Settings…") }.keyboardShortcut(",")
        Divider()
        Button("Quit OpenScout") { NSApplication.shared.terminate(nil) }.keyboardShortcut("q")
    }
}
