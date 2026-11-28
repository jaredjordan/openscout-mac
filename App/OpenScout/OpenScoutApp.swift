import OpenScoutCore
import OpenScoutMac
import SwiftUI

@main
struct OpenScoutApp: App {
    @StateObject private var model = AppModel()
    @AppStorage("finishedFirstRun") private var finishedFirstRun = false

    var body: some Scene {
        MenuBarExtra {
            MenuContent()
                .environmentObject(model)
        } label: {
            MenuBarLabel(finishedFirstRun: finishedFirstRun)
                .environmentObject(model)
        }
        .menuBarExtraStyle(.menu)

        Window("OpenScout", id: "main") {
            MainWindow()
                .environmentObject(model)
                .frame(minWidth: 860, minHeight: 520)
        }
        .defaultSize(width: 1040, height: 640)

        Window("Set Up OpenScout", id: "setup") {
            FirstRunView(finished: $finishedFirstRun)
                .environmentObject(model)
                .frame(width: 520, height: 420)
        }
        .windowResizability(.contentSize)

        Settings {
            SettingsView()
                .environmentObject(model)
        }
    }
}

/// The menu bar mark. Also starts the model and opens first run the first time.
struct MenuBarLabel: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.openWindow) private var openWindow
    let finishedFirstRun: Bool

    var body: some View {
        Image(systemName: model.mark.symbolName)
            .accessibilityLabel(model.status?.accessibilityLabel ?? "OpenScout")
            .task {
                model.start()
                if !finishedFirstRun { openWindow(id: "setup") }
            }
    }
}
