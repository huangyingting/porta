import Foundation
import NetworkExtension
import PortaKit
import SwiftUI

/// The app's state: the saved profiles (system VPN configurations), which
/// one is connected, and what its tunnel extension reports.
@MainActor
final class ProfileStore: ObservableObject {
    @Published private(set) var profiles: [VPNProfile] = []
    @Published private(set) var statuses: [String: NEVPNStatus] = [:]
    /// The connected tunnel's report, refreshed every second.
    @Published private(set) var report: TunnelReport?
    @Published private(set) var samples: [TrafficSample] = []
    @Published private(set) var downloadRate: Double = 0
    @Published private(set) var uploadRate: Double = 0
    /// Why each profile's tunnel last stopped, when it failed.
    @Published private(set) var failures: [String: String] = [:]
    @Published private(set) var log = EventLog()
    @Published private(set) var deviceID: String?
    @Published private(set) var loaded = false
    /// A profile from a setup link or QR code, waiting for the user's review.
    @Published var pendingDraft: ProfileDraft?
    /// An error to show in an alert.
    @Published var alert: String?

    nonisolated static let identityTag = "dev.porta.device-key"
    /// The keychain group shared with the tunnel extension, from Info.plist.
    nonisolated static let keychainGroup: String? = {
        guard let group = Bundle.main.object(forInfoDictionaryKey: "PortaKeychainGroup") as? String,
              !group.isEmpty, !group.hasPrefix("$(")
        else { return nil }
        return group
    }()

    private var managers: [String: NETunnelProviderManager] = [:]
    private var observer: NSObjectProtocol?
    private var timer: Timer?
    private var previous: (time: Date, sent: UInt64, received: UInt64)?
    private var sampleIndex = 0
    /// A profile to start again once it has stopped, after its routing changed.
    private var restartAfterStop: String?

    private var tunnelBundleID: String {
        (Bundle.main.bundleIdentifier ?? "dev.porta.app") + ".tunnel"
    }

    init() {
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] notification in
            guard let connection = notification.object as? NEVPNConnection else { return }
            Task { @MainActor in self?.statusChanged(connection) }
        }
        Task {
            await reload()
            await loadDeviceID()
        }
    }

    // MARK: Profiles

    var activeProfileID: String? {
        profiles.first { statuses[$0.id].map(Self.isActive) ?? false }?.id
    }

    func status(of profile: VPNProfile) -> NEVPNStatus {
        statuses[profile.id] ?? .disconnected
    }

    nonisolated static func isActive(_ status: NEVPNStatus) -> Bool {
        [.connecting, .connected, .reasserting, .disconnecting].contains(status)
    }

    func reload() async {
        do {
            let all = try await NETunnelProviderManager.loadAllFromPreferences()
            var managers: [String: NETunnelProviderManager] = [:]
            var profiles: [VPNProfile] = []
            for manager in all {
                guard let profile = Self.profile(from: manager) else { continue }
                managers[profile.id] = manager
                profiles.append(profile)
                statuses[profile.id] = manager.connection.status
            }
            self.managers = managers
            self.profiles = profiles.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        } catch {
            record("Could not load the VPN profiles: \(error.localizedDescription)")
        }
        loaded = true
        updatePolling()
    }

    private static func profile(from manager: NETunnelProviderManager) -> VPNProfile? {
        guard let protocolConfiguration = manager.protocolConfiguration as? NETunnelProviderProtocol,
              let options = protocolConfiguration.providerConfiguration,
              let id = options["profileID"] as? String
        else { return nil }
        return VPNProfile(
            id: id,
            name: manager.localizedDescription ?? "Porta",
            server: protocolConfiguration.serverAddress ?? "",
            backupServers: options["backupServers"] as? [String] ?? [],
            relayAddress: options["relayAddress"] as? String ?? "",
            allowLocalNetwork: protocolConfiguration.excludeLocalNetworks,
            connectAutomatically: options["connectAutomatically"] as? Bool ?? false
        )
    }

    /// Saves a new or edited profile as a system VPN configuration. The
    /// first save asks the user to allow Porta to add VPN configurations.
    func save(_ draft: ProfileDraft) async throws {
        let id = draft.profileID ?? UUID().uuidString
        let manager = managers[id] ?? NETunnelProviderManager()
        let previous = manager.protocolConfiguration as? NETunnelProviderProtocol
        let configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = tunnelBundleID
        configuration.serverAddress = draft.trimmedServer
        if draft.trimmedToken.isEmpty, let reference = previous?.passwordReference {
            configuration.passwordReference = reference
        } else {
            configuration.passwordReference = try TokenStore.save(
                token: draft.trimmedToken, profileID: id, accessGroup: Self.keychainGroup
            )
        }
        let fullTunnel = previous?.providerConfiguration?["fullTunnel"] as? Bool ?? true
        var options: [String: Any] = [
            "profileID": id,
            "backupServers": draft.backupList,
            "transport": "auto",
            "identityTag": Self.identityTag,
            "connectAutomatically": draft.connectAutomatically,
            "fullTunnel": fullTunnel,
        ]
        if let group = Self.keychainGroup { options["accessGroup"] = group }
        if !draft.trimmedRelay.isEmpty { options["relayAddress"] = draft.trimmedRelay }
        configuration.providerConfiguration = options
        // A full tunnel fails closed: nothing leaves outside it, even while
        // it reconnects. Split tunnels route only the gateway's networks.
        configuration.includeAllNetworks = fullTunnel
        configuration.excludeLocalNetworks = draft.allowLocalNetwork
        manager.protocolConfiguration = configuration
        manager.localizedDescription = draft.trimmedName
        let rule = NEOnDemandRuleConnect()
        rule.interfaceTypeMatch = .any
        manager.onDemandRules = [rule]
        if draft.connectAutomatically {
            // Only the enabled configuration connects on demand.
            manager.isEnabled = true
            manager.isOnDemandEnabled = true
        } else {
            manager.isOnDemandEnabled = false
        }
        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        managers[id] = manager
        if draft.connectAutomatically {
            for other in profiles where other.id != id && other.connectAutomatically {
                var draft = ProfileDraft(profile: other)
                draft.connectAutomatically = false
                try? await save(draft)
            }
        }
        record(draft.profileID == nil ? "Saved profile \(draft.trimmedName)" : "Updated profile \(draft.trimmedName)")
        await reload()
    }

    func delete(_ profile: VPNProfile) async {
        guard let manager = managers[profile.id] else { return }
        do {
            try await manager.removeFromPreferences()
            TokenStore.delete(profileID: profile.id, accessGroup: Self.keychainGroup)
            failures[profile.id] = nil
            record("Deleted profile \(profile.name)")
        } catch {
            alert = String(localized: "Could not delete the VPN profile: \(error.localizedDescription)")
        }
        await reload()
    }

    // MARK: Connecting

    func connect(_ profile: VPNProfile) async {
        guard let manager = managers[profile.id] else { return }
        if let active = activeProfileID, active != profile.id {
            alert = String(localized: "Disconnect the active profile before connecting another one.")
            return
        }
        failures[profile.id] = nil
        do {
            // Only one configuration is enabled at a time; enabling this one
            // disables the others.
            manager.isEnabled = true
            manager.isOnDemandEnabled = profile.connectAutomatically
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            try manager.connection.startVPNTunnel()
            record("Connecting \(profile.name) to \(profile.server)")
        } catch {
            failures[profile.id] = error.localizedDescription
            record("Could not start \(profile.name): \(error.localizedDescription)")
        }
    }

    func disconnect(_ profile: VPNProfile) async {
        guard let manager = managers[profile.id] else { return }
        // On demand would connect it straight back.
        if manager.isOnDemandEnabled {
            manager.isOnDemandEnabled = false
            try? await manager.saveToPreferences()
        }
        manager.connection.stopVPNTunnel()
        record("Disconnecting \(profile.name)")
    }

    private func statusChanged(_ connection: NEVPNConnection) {
        guard let id = managers.first(where: { $0.value.connection === connection })?.key else {
            Task { await reload() }
            return
        }
        let before = statuses[id]
        statuses[id] = connection.status
        let name = profiles.first { $0.id == id }?.name ?? ""
        if connection.status == .disconnected, let before, before != .disconnected {
            record("\(name): disconnected")
            connection.fetchLastDisconnectError { [weak self] error in
                guard let error else { return }
                let message = Messages.describe(error)
                Task { @MainActor in
                    self?.failures[id] = message
                    self?.record("\(name): \(message)")
                }
            }
            if restartAfterStop == id {
                restartAfterStop = nil
                if let profile = profiles.first(where: { $0.id == id }) {
                    Task { await connect(profile) }
                }
            }
        } else if connection.status == .connected {
            record("\(name): connected")
        }
        updatePolling()
    }

    // MARK: The tunnel's report

    private func updatePolling() {
        let polling = activeProfileID != nil
        if polling, timer == nil {
            timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
                Task { @MainActor in self?.poll() }
            }
            poll()
        } else if !polling {
            timer?.invalidate()
            timer = nil
            report = nil
            previous = nil
            downloadRate = 0
            uploadRate = 0
        }
    }

    private func poll() {
        guard let id = activeProfileID,
              let session = managers[id]?.connection as? NETunnelProviderSession
        else { return }
        do {
            try session.sendProviderMessage(TunnelReport.request) { [weak self] data in
                guard let data, let report = TunnelReport.decode(data) else { return }
                Task { @MainActor in self?.received(report, profileID: id) }
            }
        } catch {
            // The extension is not running yet; the next tick tries again.
        }
    }

    private func received(_ report: TunnelReport, profileID: String) {
        self.report = report
        let now = Date()
        // A restarted extension starts counting again.
        if let previous, report.bytesReceived >= previous.received, report.bytesSent >= previous.sent {
            let seconds = max(now.timeIntervalSince(previous.time), 0.001)
            downloadRate = Double(report.bytesReceived - previous.received) / seconds
            uploadRate = Double(report.bytesSent - previous.sent) / seconds
        }
        previous = (now, report.bytesSent, report.bytesReceived)
        sampleIndex += 1
        samples.append(TrafficSample(id: sampleIndex, download: downloadRate, upload: uploadRate))
        if samples.count > 60 { samples.removeFirst(samples.count - 60) }
        if let info = report.info {
            adjustRouting(profileID: profileID, fullTunnel: info.fullTunnel)
        }
    }

    /// A configuration that includes all networks sends everything into the
    /// tunnel, which a split-tunnel gateway does not route; the system only
    /// reads the setting when the tunnel starts, so it reconnects once.
    private func adjustRouting(profileID: String, fullTunnel: Bool) {
        guard let manager = managers[profileID],
              let configuration = manager.protocolConfiguration as? NETunnelProviderProtocol,
              configuration.includeAllNetworks != fullTunnel,
              restartAfterStop == nil
        else { return }
        configuration.includeAllNetworks = fullTunnel
        var options = configuration.providerConfiguration ?? [:]
        options["fullTunnel"] = fullTunnel
        configuration.providerConfiguration = options
        manager.protocolConfiguration = configuration
        restartAfterStop = profileID
        record(fullTunnel
            ? "The gateway now uses a full tunnel; reconnecting to protect all traffic"
            : "The gateway uses a split tunnel; reconnecting so other traffic stays on this network")
        Task {
            do {
                try await manager.saveToPreferences()
                try await manager.loadFromPreferences()
                manager.connection.stopVPNTunnel()
            } catch {
                restartAfterStop = nil
                record("Could not update the routing: \(error.localizedDescription)")
            }
        }
    }

    // MARK: Setup links and the log

    /// Opens the editor for a `porta://profile` setup link.
    func openSetupLink(_ link: String) {
        do {
            pendingDraft = ProfileDraft(setup: try Profile(setupLink: link.trimmingCharacters(in: .whitespacesAndNewlines)))
        } catch {
            alert = String(localized: "This is not a valid Porta profile. Scan the setup QR code or copy setup from the client download page, then try again.")
        }
    }

    func record(_ message: String) {
        log.append(message)
    }

    func clearLog() {
        log.removeAll()
        clearedAt = Date()
    }

    /// Log entries older than this were cleared, including the tunnel's.
    private(set) var clearedAt = Date.distantPast

    /// The app's and the tunnel's events, oldest first.
    var combinedLog: [LogEntry] {
        ((report?.log ?? []) + log.entries)
            .filter { $0.time > clearedAt }
            .sorted { $0.time < $1.time }
    }

    private func loadDeviceID() async {
        let id = await Task.detached { () -> String? in
            try? DeviceIdentity.loadOrCreate(
                tag: ProfileStore.identityTag,
                accessGroup: ProfileStore.keychainGroup,
                deviceName: "Porta"
            ).deviceID
        }.value
        deviceID = id
    }
}
