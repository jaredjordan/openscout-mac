import AppKit
import OpenScoutCore
import SwiftUI

/// Every claim on this panel comes from the file itself.
struct FindingInspector: View {
    @EnvironmentObject var model: AppModel
    let finding: Finding
    @State private var confirmingAllow = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text(finding.title).font(.title2.bold())
                Text(finding.summary)
                Text(finding.recommendation)
                    .font(.body.bold())
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
                EvidenceList(evidence: finding.evidence)
                HStack {
                    Button("Quarantine") { model.quarantine(finding) }
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.return, modifiers: [.command])
                    Button("Allow…") { confirmingAllow = true }
                    Button("Show in Finder") {
                        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: finding.evidence.path)])
                    }
                }
                Button("Report False Positive") { reportFalsePositive() }
                    .buttonStyle(.link)
            }
            .padding()
        }
        .confirmationDialog("Allow \(URL(fileURLWithPath: finding.evidence.path).lastPathComponent)?",
                            isPresented: $confirmingAllow, titleVisibility: .visible) {
            Button("Allow This Exact File", role: .destructive) { model.allowConfirmed(finding) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("It stays where it is and keeps running. OpenScout won't flag these exact bytes again. If the file changes, it's checked again.")
        }
    }

    /// Opens a prefilled GitHub issue with the full evidence, so the report can be acted on.
    private func reportFalsePositive() {
        let e = finding.evidence
        let body = """
        Rule: \(e.ruleID)
        Engine: \(e.engine.rawValue)
        SHA-256: \(e.sha256 ?? "unknown")
        Definitions: \(e.definitionsVersion ?? "unknown")
        Signer: \(e.signer ?? "none")
        Team ID: \(e.teamID ?? "none")
        Match: \(e.matchDetail ?? "none")
        """
        var components = URLComponents(string: "https://github.com/jaredjordan/openscout-mac/issues/new")!
        components.queryItems = [URLQueryItem(name: "title", value: "False positive: \(e.ruleID)"),
                                 URLQueryItem(name: "labels", value: "detection"),
                                 URLQueryItem(name: "body", value: body)]
        if let url = components.url { NSWorkspace.shared.open(url) }
    }
}

struct EvidenceList: View {
    @EnvironmentObject var model: AppModel
    let evidence: Evidence

    var body: some View {
        Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 8) {
            row("File", model.display(evidence.path), copy: evidence.path)
            row("SHA-256", evidence.sha256 ?? "Not computed", copy: evidence.sha256)
            row("Engine", evidence.engine.rawValue)
            row("Rule", evidence.ruleID, copy: evidence.ruleID)
            if let match = evidence.matchDetail { row("Match", match, copy: match) }
            row("Definitions", evidence.definitionsVersion ?? "Not applicable")
            row("Signed by", evidence.signer ?? "Nobody")
            row("Team ID", evidence.teamID ?? "None", copy: evidence.teamID)
            if let notarized = evidence.notarized { row("Notarized", notarized ? "Yes" : "No") }
        }
    }

    @ViewBuilder
    private func row(_ label: String, _ value: String, copy: String? = nil) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value).textSelection(.enabled).lineLimit(3)
            if let copy {
                Button("Copy") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(copy, forType: .string)
                }
                .controlSize(.small)
            } else {
                Text("")
            }
        }
    }
}

struct QuarantineView: View {
    @EnvironmentObject var model: AppModel
    @State private var selection: QuarantineRecord.ID?

    var body: some View {
        List(model.quarantine, selection: $selection) { record in
            VStack(alignment: .leading) {
                Text(URL(fileURLWithPath: record.originalPath).lastPathComponent).font(.headline)
                Text("Quarantined \(record.quarantinedAt.formatted(date: .abbreviated, time: .shortened))")
                    .foregroundStyle(.secondary)
            }
            .tag(record.id)
        }
        .overlay {
            if model.quarantine.isEmpty {
                ContentUnavailableView("Quarantine is empty", systemImage: "archivebox")
            }
        }
        .navigationTitle("Quarantine")
        .inspector(isPresented: .constant(true)) {
            if let record = model.quarantine.first(where: { $0.id == selection }) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 14) {
                        Text(URL(fileURLWithPath: record.originalPath).lastPathComponent).font(.title2.bold())
                        Text("Moved here by rule \(record.finding.evidence.ruleID).")
                        EvidenceList(evidence: record.finding.evidence)
                        Text("What Restore does").font(.headline)
                        Text("Puts it back where it was, with the same permissions, and allows this exact file so it isn't flagged again. A changed file is still checked.")
                        Button("Restore") { model.restore(record) }.buttonStyle(.borderedProminent)
                    }
                    .padding()
                }
            } else {
                ContentUnavailableView("Select an item", systemImage: "sidebar.right")
            }
        }
    }
}
