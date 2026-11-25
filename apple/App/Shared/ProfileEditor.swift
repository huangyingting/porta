import SwiftUI

/// Adds or edits a profile. Saving validates it as the other clients do.
struct ProfileEditor: View {
    @EnvironmentObject private var store: ProfileStore
    @Environment(\.dismiss) private var dismiss
    @State var draft: ProfileDraft
    @State private var problem: String?
    @State private var saving = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Profile name", text: $draft.name, prompt: Text("Home, Work, Lab…"))
                    TextField("Gateway", text: $draft.server, prompt: Text("https://vpn.example.com"))
                        .addressEntry()
                    SecureField(
                        "Access token",
                        text: $draft.token,
                        prompt: Text(draft.profileID == nil ? LocalizedStringKey("Access token") : "Leave blank to keep the current token")
                    )
                    .addressEntry()
                } footer: {
                    Text("Device identity uses a security key on this device; its name or model is shown for recognition.")
                }
                Section {
                    TextField("Backup gateways", text: $draft.backupServers, prompt: Text("Optional, one per line: gateways sharing this account"), axis: .vertical)
                        .lineLimit(1 ... 4)
                        .addressEntry()
                    TextField("Relay address", text: $draft.relayAddress, prompt: Text("Optional IP:port of a relay to the gateway"))
                        .addressEntry()
                } header: {
                    Text("Optional")
                }
                Section {
                    Toggle(isOn: $draft.allowLocalNetwork) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Allow local network")
                            Text("Keep printers, file shares and casting on this network reachable while everything else uses the tunnel.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    Toggle(isOn: $draft.connectAutomatically) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Connect automatically")
                            Text("Keeps this profile connected whenever a network is available. Only one profile can connect automatically.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                if let problem {
                    Section {
                        Text(problem)
                            .foregroundStyle(.red)
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle(draft.profileID == nil ? LocalizedStringKey("Add profile") : "Edit profile")
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { save() }
                        .disabled(saving)
                }
            }
        }
        #if os(macOS)
        .frame(minWidth: 460, minHeight: 520)
        #endif
    }

    private func save() {
        if let problem = draft.problem() {
            self.problem = problem
            return
        }
        problem = nil
        saving = true
        Task {
            do {
                try await store.save(draft)
                dismiss()
            } catch {
                problem = Messages.describe(error)
            }
            saving = false
        }
    }
}

extension View {
    /// Fields for addresses and tokens: no capitals or corrections.
    func addressEntry() -> some View {
        #if os(iOS)
        return self
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .keyboardType(.asciiCapable)
        #else
        return autocorrectionDisabled()
        #endif
    }
}
