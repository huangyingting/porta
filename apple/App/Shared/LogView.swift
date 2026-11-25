import PortaKit
import SwiftUI

/// The app's and the tunnel's recent events. Tokens are never logged.
struct LogView: View {
    @EnvironmentObject private var store: ProfileStore
    @Environment(\.dismiss) private var dismiss
    @State private var copied = false

    var body: some View {
        NavigationStack {
            List {
                if let deviceID = store.deviceID {
                    Section {
                        LabeledContent("Device ID", value: deviceID)
                            .textSelection(.enabled)
                        LabeledContent("Version", value: Self.version)
                    }
                }
                Section {
                    if store.combinedLog.isEmpty {
                        Text("No connection events yet.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(store.combinedLog.reversed()) { entry in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(entry.time.formatted(date: .numeric, time: .standard))
                                .font(.caption.monospacedDigit())
                                .foregroundStyle(.secondary)
                            Text(entry.message)
                                .font(.callout)
                                .textSelection(.enabled)
                        }
                    }
                } footer: {
                    Text("The log stays on this device. It contains addresses and the device name, so share it only with your administrator.")
                }
            }
            .navigationTitle("Connection log")
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { dismiss() }
                }
                ToolbarItem(placement: .primaryAction) {
                    Button(copied ? LocalizedStringKey("Copied") : "Copy log") {
                        Pasteboard.string = text
                        copied = true
                    }
                }
                ToolbarItem(placement: .destructiveAction) {
                    Button("Clear", role: .destructive) { store.clearLog() }
                }
            }
        }
        #if os(macOS)
        .frame(minWidth: 520, minHeight: 480)
        #endif
    }

    private var text: String {
        var lines = ["Porta \(Self.version)"]
        if let deviceID = store.deviceID { lines.append("Device \(deviceID)") }
        for entry in store.combinedLog {
            lines.append("\(entry.time.formatted(.iso8601)) \(entry.message)")
        }
        return lines.joined(separator: "\n")
    }

    static var version: String {
        let short = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"
        return "\(short) (\(build))"
    }
}
