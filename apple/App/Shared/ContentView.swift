import Charts
import NetworkExtension
import PortaKit
import SwiftUI

/// The main screen: the connection, live traffic and the profiles, as in
/// the other Porta clients.
struct ContentView: View {
    @EnvironmentObject private var store: ProfileStore
    @State private var editing: ProfileDraft?
    @State private var deleting: VPNProfile?
    @State private var showingLog = false
    @State private var scanning = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    StatusView()
                }
                Section {
                    TrafficView()
                }
                Section {
                    if store.profiles.isEmpty {
                        emptyState
                    } else {
                        ForEach(store.profiles) { profile in
                            ProfileRow(profile: profile)
                                .swipeActions(edge: .trailing) {
                                    Button(role: .destructive) { deleting = profile } label: {
                                        Label("Delete", systemImage: "trash")
                                    }
                                    .disabled(ProfileStore.isActive(store.status(of: profile)))
                                }
                                .swipeActions(edge: .leading) {
                                    Button { edit(profile) } label: {
                                        Label("Edit", systemImage: "pencil")
                                    }
                                    .tint(.accentColor)
                                }
                                .contextMenu {
                                    Button { edit(profile) } label: { Label("Edit", systemImage: "pencil") }
                                    Button(role: .destructive) { deleting = profile } label: {
                                        Label("Delete", systemImage: "trash")
                                    }
                                }
                        }
                    }
                } header: {
                    Text("VPN profiles")
                } footer: {
                    if !store.profiles.isEmpty {
                        #if os(iOS)
                        Text("Swipe a profile to edit or delete it.")
                        #else
                        Text("Control-click a profile to edit or delete it.")
                        #endif
                    }
                }
            }
            .navigationTitle("Porta")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    addMenu
                }
                ToolbarItem(placement: .secondaryAction) {
                    Button { showingLog = true } label: { Label("Log", systemImage: "list.bullet.rectangle") }
                }
            }
            .sheet(item: $editing) { draft in
                ProfileEditor(draft: draft)
            }
            .sheet(isPresented: $showingLog) {
                LogView()
            }
            #if os(iOS)
            .fullScreenCover(isPresented: $scanning) {
                QRScannerSheet { link in
                    scanning = false
                    store.openSetupLink(link)
                }
            }
            #endif
            .confirmationDialog(
                "Delete profile?",
                isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } }),
                titleVisibility: .visible,
                presenting: deleting
            ) { profile in
                Button("Delete", role: .destructive) {
                    Task { await store.delete(profile) }
                }
            } message: { profile in
                Text("Delete “\(profile.name)” from this device? This does not delete the server account or release its device slot.")
            }
            .alert("Porta", isPresented: Binding(get: { store.alert != nil }, set: { if !$0 { store.alert = nil } })) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(store.alert ?? "")
            }
            .onChange(of: store.pendingDraft) { draft in
                guard let draft else { return }
                store.pendingDraft = nil
                editing = draft
            }
        }
    }

    private var addMenu: some View {
        Menu {
            #if os(iOS)
            Button { scanning = true } label: { Label("Scan QR code", systemImage: "qrcode.viewfinder") }
            #endif
            Button { pasteSetup() } label: { Label("Paste setup", systemImage: "doc.on.clipboard") }
            Button { editing = ProfileDraft() } label: { Label("Enter manually", systemImage: "square.and.pencil") }
        } label: {
            Label("Add profile", systemImage: "plus")
        }
    }

    private var emptyState: some View {
        VStack(spacing: 8) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.largeTitle)
                .foregroundStyle(.tint)
            Text("No VPN profiles")
                .font(.headline)
            Text("Add the profile from your Porta downloads page to start a secure connection.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            addMenu
                .menuStyle(.borderlessButton)
                .fixedSize()
                .padding(.top, 4)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 16)
    }

    private func edit(_ profile: VPNProfile) {
        if ProfileStore.isActive(store.status(of: profile)) {
            store.alert = String(localized: "Disconnect this profile before editing it.")
        } else {
            editing = ProfileDraft(profile: profile)
        }
    }

    private func pasteSetup() {
        guard let text = Pasteboard.string, !text.isEmpty else {
            store.alert = String(localized: "Copy setup on your Porta downloads page first, then choose Paste setup.")
            return
        }
        store.openSetupLink(text)
    }
}

/// The connection: its state and, when connected, how and with what limits.
struct StatusView: View {
    @EnvironmentObject private var store: ProfileStore

    var body: some View {
        let active = store.profiles.first { $0.id == store.activeProfileID }
        let status = active.map { store.status(of: $0) } ?? .disconnected
        HStack(alignment: .top, spacing: 14) {
            Circle()
                .fill(color(status))
                .frame(width: 12, height: 12)
                .padding(.top, 6)
            VStack(alignment: .leading, spacing: 4) {
                Text(Messages.state(status))
                    .font(.title3.weight(.semibold))
                if status == .connected, let info = store.report?.info {
                    Text(Messages.transport(info))
                    Text(Messages.routing(info))
                    if let account = Messages.account(info.account) {
                        Text(account)
                            .foregroundStyle(Messages.accountNeedsAttention(info.account) ? Color.orange : Color.secondary)
                    }
                    if let connectedAt = store.report?.connectedAt {
                        Text("Connected since \(connectedAt.formatted(date: .omitted, time: .shortened)) · \(info.address)")
                    }
                } else if status == .connecting || status == .reasserting {
                    Text(status == .connecting ? LocalizedStringKey("Establishing a secure tunnel…") : "Restoring the secure tunnel…")
                } else if let failure = store.profiles.compactMap({ store.failures[$0.id] }).first {
                    Text(failure)
                        .foregroundStyle(.red)
                } else {
                    Text(store.profiles.isEmpty ? LocalizedStringKey("Add a profile to connect.") : "Choose a VPN profile to connect.")
                }
            }
            .font(.subheadline)
            .foregroundStyle(.secondary)
        }
        .padding(.vertical, 6)
    }

    private func color(_ status: NEVPNStatus) -> Color {
        switch status {
        case .connected: return .green
        case .connecting, .reasserting, .disconnecting: return .orange
        default: return .gray
        }
    }
}

/// Download and upload over the last minute.
struct TrafficView: View {
    @EnvironmentObject private var store: ProfileStore

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Real-time traffic")
                    .font(.footnote.weight(.semibold))
                    .textCase(.uppercase)
                    .foregroundStyle(.secondary)
                Spacer()
                Text(store.report == nil ? LocalizedStringKey("Idle") : "● Live")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(store.report == nil ? Color.secondary : Color.green)
            }
            Chart(store.samples) { sample in
                LineMark(x: .value("Time", sample.id), y: .value("Bytes per second", sample.download), series: .value("Direction", "download"))
                    .foregroundStyle(Color.accentColor)
                LineMark(x: .value("Time", sample.id), y: .value("Bytes per second", sample.upload), series: .value("Direction", "upload"))
                    .foregroundStyle(Color.blue)
            }
            .chartXAxis(.hidden)
            .chartYAxis(.hidden)
            .frame(height: 90)
            HStack {
                Label(Messages.rate(store.downloadRate), systemImage: "arrow.down")
                    .foregroundStyle(Color.accentColor)
                Spacer()
                Label(Messages.rate(store.uploadRate), systemImage: "arrow.up")
                    .foregroundStyle(Color.blue)
            }
            .font(.subheadline.weight(.semibold))
            Text("Downloaded \(Messages.bytes(store.report?.bytesReceived ?? 0)) · Uploaded \(Messages.bytes(store.report?.bytesSent ?? 0))")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 6)
    }
}

/// One profile with its connection switch.
struct ProfileRow: View {
    @EnvironmentObject private var store: ProfileStore
    let profile: VPNProfile

    var body: some View {
        let status = store.status(of: profile)
        HStack(spacing: 12) {
            Text(profile.initial)
                .font(.headline)
                .foregroundStyle(.tint)
                .frame(width: 40, height: 40)
                .background(Circle().fill(Color.accentColor.opacity(0.15)))
            VStack(alignment: .leading, spacing: 2) {
                Text(profile.name)
                    .font(.headline)
                Text(profile.displayServer)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Text(detail(status))
                    .font(.caption)
                    .foregroundStyle(status == .connected ? Color.green : Color.secondary)
            }
            Spacer()
            Toggle(isOn: Binding(
                get: { status == .connected || status == .connecting || status == .reasserting },
                set: { on in
                    Task {
                        if on {
                            await store.connect(profile)
                        } else {
                            await store.disconnect(profile)
                        }
                    }
                }
            )) {
                Text(profile.name)
            }
            .labelsHidden()
            .disabled(status == .disconnecting)
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .combine)
    }

    private func detail(_ status: NEVPNStatus) -> String {
        if status != .disconnected && status != .invalid {
            return Messages.state(status)
        }
        return profile.connectAutomatically ? String(localized: "Connects automatically") : String(localized: "Ready")
    }
}
