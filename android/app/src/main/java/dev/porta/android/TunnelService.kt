package dev.porta.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.drawable.Icon
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import portamobile.Portamobile
import portamobile.Dialer
import portamobile.NativeFailureKind
import portamobile.Protector
import portamobile.ProofProvider
import portamobile.Session
import portamobile.nativeFailureKind
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.EOFException
import java.io.IOException
import java.net.URI
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import org.json.JSONObject

class TunnelService : VpnService() {
    private val running = AtomicBoolean(false)
    private val generation = AtomicLong(0)
    private val uploadedBytes = AtomicLong(0)
    private val downloadedBytes = AtomicLong(0)
    private val descriptor = AtomicReference<ParcelFileDescriptor?>()
    private val vpnReaderFailure = AtomicReference<Exception?>()
    private val failClosed = AtomicBoolean(false)
    private val selectedNetwork = AtomicReference<Network?>()
    private val preferredNetwork = AtomicReference<Network?>()
    private val uplinkPacketPool = PacketBufferPool(
        bufferSize = MAX_VPN_PACKET_SIZE,
        maxCachedBuffers = 128,
    )
    private val outboundPackets = BoundedPacketQueue(
        PacketQueueConfig(
            maxPackets = 512,
            maxBytes = 512 * MAX_VPN_PACKET_SIZE,
            tcpMaxAgeMillis = 0,
            datagramMaxAgeMillis = 0,
            controlMaxAgeMillis = 0,
            replacementPolicy = PacketQueueReplacementPolicy.DROP_OLDEST,
        ),
    )
    private val nativeSession = AtomicReference<Session?>()
    private val nativeDialer = AtomicReference<Dialer?>()
    private var input: FileInputStream? = null
    private var output: FileOutputStream? = null
    private var worker: Thread? = null
    private var statsWorker: Thread? = null
    private var vpnReader: Thread? = null
    private var vpnConfiguration: VpnConfiguration? = null

    override fun onCreate() {
        super.onCreate()
        Portamobile.initialize(this)
        createNotificationChannel()
    }

    @Synchronized
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopTunnel("Disconnected")
            return START_NOT_STICKY
        }
        if (intent?.action != ACTION_START || running.getAndSet(true)) return START_NOT_STICKY
        val runGeneration = nextSessionId.incrementAndGet()
        generation.set(runGeneration)

        val server = intent.getStringExtra(EXTRA_SERVER).orEmpty()
        val token = intent.getStringExtra(EXTRA_TOKEN).orEmpty()
        val profileId = intent.getStringExtra(EXTRA_PROFILE_ID).orEmpty()
        val profileLabel = intent.getStringExtra(EXTRA_PROFILE_NAME).orEmpty()
        if (!isHttpsOrigin(server) || !isValidToken(token)) {
            logEvent("Connection rejected: invalid profile configuration")
            stopTunnel("Invalid tunnel configuration")
            return START_NOT_STICKY
        }
        currentProfileId = profileId.ifBlank { server }
        currentProfileName = profileLabel.ifBlank { profileName(server) }
        currentSessionId = runGeneration
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification("Connecting"), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification("Connecting"))
        }
        val deviceIdentity = try {
            androidDeviceIdentity(this)
        } catch (error: DeviceIdentityUnavailableException) {
            logEvent("Device identity failed: ${error.message.orEmpty()}")
            stopTunnel(getString(R.string.device_identity_unavailable))
            return START_NOT_STICKY
        }
        val clientId = deviceIdentity.id
        uploadedBytes.set(0)
        downloadedBytes.set(0)
        failClosed.set(false)
        currentSnapshot = TrafficSnapshot()
        resetConnectionDetailsState()
        logEvent("Porta ${Portamobile.version()}; protocol ${PacketFraming.VERSION}")
        logEvent(
            "Device: ${redactDiagnosticMessage(deviceIdentity.name, token)} " +
                "(${redactDiagnosticMessage(clientId, token)}; " +
                if (deviceIdentity.hardwareBacked) "hardware-backed key)" else "Android Keystore key)",
        )
        logEvent("Connecting ${currentProfileName} to ${redactDiagnosticMessage(server, token)}")

        sendStatus("Connecting")
        startStats(runGeneration)
        worker = Thread(
            { runTunnel(server, token, deviceIdentity, runGeneration, startId) },
            "porta-transport",
        ).also { it.start() }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        stopTunnel("VPN permission revoked")
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel("Disconnected")
        super.onDestroy()
    }

    private fun runTunnel(
        server: String,
        token: String,
        deviceIdentity: AndroidDeviceIdentity,
        runGeneration: Long,
        startId: Int,
    ) {
        val clientId = deviceIdentity.id
        val backoff = ReconnectBackoff(clientId)
        var finalStatus = "Disconnected"
        var retainVpn = false
        try {
            while (isRunActive(runGeneration)) {
                val network = underlyingNetwork()
                if (network == null) {
                    logEvent("No usable underlying network")
                    if (!waitForRetry("Waiting for a network", backoff.nextDelayMillis(), runGeneration)) break
                    continue
                }
                val attemptToken = synchronized(this) {
                    if (!isRunActive(runGeneration)) return
                    selectedNetwork.set(network)
                    preferredNetwork.compareAndSet(network, null)
                    setUnderlyingNetworks(arrayOf(network))
                    beginConnectionAttempt(runGeneration)
                }
                val selectedNetworkType = networkType(network)
                val attemptActive = AtomicBoolean(true)
                val networkChange = AtomicReference<IOException?>()
                var networkCallback: SelectedNetworkCallbacks? = null
                var attemptConnectedAt = 0L
                try {
                    networkCallback = registerSelectedNetworkCallback(
                        network,
                        attemptActive,
                        runGeneration,
                    ) { reason ->
                        if (networkChange.compareAndSet(null, IOException(reason))) {
                            cancelCurrentTransportAttempt()
                        }
                    }
                    val reconnecting = descriptor.get() != null
                    updateConnectionStatus(if (reconnecting) "Reconnecting" else "Connecting", runGeneration)
                    logEvent(formatAttemptEvent("Automatic HTTP/3 or HTTP/2", selectedNetworkType))
                    connectNativeOnce(
                        server,
                        token,
                        deviceIdentity,
                        network,
                        attemptActive,
                        attemptToken,
                        selectedNetworkType,
                        runGeneration,
                    ) {
                        attemptConnectedAt = System.currentTimeMillis()
                    }
                    networkChange.get()?.let { throw it }
                } catch (error: PermanentTunnelException) {
                    if (!isRunActive(runGeneration)) break
                    val detail = safeErrorMessage(error, token)
                    retainVpn = descriptor.get() != null
                    finalStatus = if (retainVpn) {
                        "Connection blocked: $detail"
                    } else {
                        "Connection rejected: $detail"
                    }
                    clearConnectionDetails(attemptToken)
                    logEvent(finalStatus)
                    break
                } catch (error: Exception) {
                    if (!isRunActive(runGeneration)) break
                    logEvent("Connection interrupted: ${safeErrorMessage(error, token)}")
                    clearConnectionDetails(attemptToken)
                    if (attemptConnectedAt != 0L &&
                        System.currentTimeMillis() - attemptConnectedAt >= STABLE_CONNECTION_MILLIS
                    ) {
                        backoff.reset()
                    }
                    synchronized(this) {
                        if (isRunActive(runGeneration)) selectedNetwork.set(null)
                    }
                    if (!waitForRetry("Connection lost", backoff.nextDelayMillis(), runGeneration)) break
                } finally {
                    networkCallback?.let(::unregisterNetworkCallback)
                    attemptActive.set(false)
                }
            }
        } finally {
            if (!retainVpn || !holdVpnAfterTerminalFailure(runGeneration, finalStatus)) {
                finishTunnel(runGeneration, startId, finalStatus)
            }
        }
    }

    private fun connectNativeOnce(
        server: String,
        token: String,
        deviceIdentity: AndroidDeviceIdentity,
        network: Network,
        attemptActive: AtomicBoolean,
        attemptToken: ConnectionAttemptToken,
        selectedNetworkType: String?,
        runGeneration: Long,
        onConnected: () -> Unit,
    ) {
        val attemptStartedAt = System.nanoTime()
        val host = gatewayHost(server)
            ?: throw PermanentTunnelException("Gateway URL has no hostname")
        if (!attemptActive.get()) throw IOException("Underlying network changed before connection")
        val remoteAddresses = try {
            network.getAllByName(host).mapNotNull { it.hostAddress }.distinct()
        } catch (error: UnknownHostException) {
            throw IOException("Could not resolve the gateway on the underlying network", error)
        }
        if (remoteAddresses.isEmpty()) {
            throw IOException("Gateway hostname resolved to no addresses")
        }

        val protector = object : Protector {
            override fun prepare(fd: Int): String {
                if (!this@TunnelService.protect(fd)) {
                    return "configuration: Android refused to protect the transport socket"
                }
                return try {
                    ParcelFileDescriptor.fromFd(fd).use { socket ->
                        network.bindSocket(socket.fileDescriptor)
                    }
                    ""
                } catch (error: IOException) {
                    "transport unavailable: could not bind the transport socket to the selected network"
                }
            }
        }
        val proofProvider = ProofProvider { method, path ->
            val proof = deviceIdentity.proof(token, method, path)
            JSONObject()
                .put("publicKey", proof.publicKey)
                .put("timestamp", proof.timestamp)
                .put("nonce", proof.nonce)
                .put("signature", proof.signature)
                .put("deviceName", deviceIdentity.name)
                .toString()
        }
        val dialer = Portamobile.newDialer()
        val readerFailureBeforeDial = synchronized(this) {
            if (!isRunActive(runGeneration)) {
                closeDialer(dialer)
                throw InterruptedException("Tunnel generation was replaced")
            }
            if (!nativeDialer.compareAndSet(null, dialer)) {
                closeDialer(dialer)
                throw IOException("Another native connection attempt is active")
            }
            vpnReaderFailure.get()
        }
        var session: Session? = null
        var unavailable: Exception? = null
        var connected = false
        try {
            for (remoteAddress in remoteAddresses) {
                try {
                    if (!isRunActive(runGeneration)) throw InterruptedException("Tunnel stopped")
                    if (!attemptActive.get()) {
                        throw IOException("Underlying network changed during connection")
                    }
                    session = dialer.dial(
                        server,
                        token,
                        remoteAddress,
                        proofProvider,
                        protector,
                    )
                    connected = true
                    break
                } catch (error: Exception) {
                    if (!isRunActive(runGeneration)) throw InterruptedException("Tunnel stopped")
                    if (!attemptActive.get()) {
                        throw IOException("Underlying network changed during connection", error)
                    }
                    if (hasNewVpnReaderFailure(readerFailureBeforeDial, vpnReaderFailure.get())) {
                        throw IOException("VPN packet reader stopped", error)
                    }
                    val message = error.message.orEmpty()
                    when {
                        Portamobile.isTransportUnavailable(message) -> unavailable = error
                        Portamobile.isRetryable(message) -> throw IOException(message, error)
                        else -> throw PermanentTunnelException(message.ifBlank { "Native tunnel rejected" })
                    }
                }
            }
        } finally {
            if (!connected) {
                nativeDialer.compareAndSet(dialer, null)
                closeDialer(dialer)
            }
        }
        val activeSession = session
            ?: throw IOException(unavailable?.message ?: "No supported tunnel transport is available")
        synchronized(this) {
            if (!isRunActive(runGeneration) || !nativeSession.compareAndSet(null, activeSession)) {
                nativeDialer.compareAndSet(dialer, null)
                closeDialer(dialer)
                activeSession.close()
                throw IOException("Native tunnel was stopped or replaced")
            }
        }

        val senderError = AtomicReference<Exception?>()
        val sender = Thread({
            try {
                while (isRunActive(runGeneration) && attemptActive.get()) {
                    val packet = outboundPackets.poll(1, TimeUnit.SECONDS) ?: continue
                    if (!isRunActive(runGeneration) || !attemptActive.get()) {
                        packet.release()
                        break
                    }
                    try {
                        activeSession.send(packet.copyBytes())
                        if (isRunActive(runGeneration)) {
                            uploadedBytes.addAndGet(packet.length.toLong())
                        }
                    } finally {
                        packet.release()
                    }
                }
            } catch (error: Exception) {
                if (isRunActive(runGeneration) && attemptActive.get()) {
                    senderError.compareAndSet(null, error)
                    try {
                        activeSession.close()
                    } catch (_: Exception) {
                    }
                }
            }
        }, "porta-native-upload")

        try {
            val address = "${activeSession.address()}/${activeSession.prefixLength()}"
            val dns = activeSession.dns()
            val mtu = activeSession.mtu()
            configureVpn(
                address,
                dns,
                mtu.toString(),
                runGeneration,
            )
            val transport = when (val selected = activeSession.transport()) {
                "h2" -> "multi-lane HTTP/2"
                "h3" -> "HTTP/3 MASQUE"
                else -> throw IOException("Native tunnel selected unknown transport: $selected")
            }
            val details = ConnectionTelemetry(
                transport = transport,
                mtu = mtu,
                automaticMtu = activeSession.automaticMTU(),
                mtuCeiling = activeSession.maximumMTU().takeIf { it > 0 },
                address = address,
                dns = dns,
                deliveryMode = when (activeSession.packetDeliveryMode()) {
                    "datagram" -> "datagrams"
                    "capsule" -> "capsules"
                    "framed" -> "framed packets"
                    else -> null
                },
                networkType = selectedNetworkType,
                setupDurationMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - attemptStartedAt),
                appVersion = Portamobile.version(),
                protocolVersion = PacketFraming.VERSION,
            )
            if (!publishConnectionDetails(attemptToken, details.toConnectionDetails())) {
                throw InterruptedException("Native tunnel was replaced")
            }
            val tunnelOutput = output ?: throw IOException("VPN output is unavailable")
            onConnected()
            formatConnectedEvents(details).forEach(::logEvent)
            updateConnectionStatus("Connected over $transport", runGeneration)
            sender.start()
            while (isRunActive(runGeneration) && attemptActive.get()) {
                val packet = try {
                    activeSession.receive()
                } catch (error: Exception) {
                    throw classifyNativeSessionFailure(error, "Native tunnel receive stopped")
                }
                if (!isRunActive(runGeneration) || !attemptActive.get()) break
                tunnelOutput.write(packet)
                if (isRunActive(runGeneration)) {
                    downloadedBytes.addAndGet(packet.size.toLong())
                }
            }
            if (isRunActive(runGeneration)) throw IOException("Gateway closed the native tunnel")
        } catch (error: Exception) {
            val uploadError = senderError.get()
            if (uploadError != null) {
                throw classifyNativeSessionFailure(uploadError, "Native tunnel upload stopped")
            }
            if (isRunActive(runGeneration)) throw error
        } finally {
            attemptActive.set(false)
            nativeDialer.compareAndSet(dialer, null)
            closeDialer(dialer)
            nativeSession.compareAndSet(activeSession, null)
            try {
                activeSession.close()
            } catch (_: Exception) {
            }
            sender.interrupt()
            if (sender.isAlive && sender !== Thread.currentThread()) {
                try {
                    sender.join(NATIVE_SENDER_STOP_TIMEOUT_MILLIS)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
            }
        }
    }

    private fun classifyNativeSessionFailure(error: Exception, context: String): Exception {
        val message = error.message.orEmpty().ifBlank { context }
        return when (nativeFailureKind(message)) {
            NativeFailureKind.PERMANENT -> PermanentTunnelException(message, error)
            NativeFailureKind.RETRYABLE,
            NativeFailureKind.TRANSPORT_UNAVAILABLE -> IOException("$context: $message", error)
        }
    }

    private fun configureVpn(
        addressHeader: String?,
        dnsHeader: String?,
        mtuHeader: String?,
        runGeneration: Long,
    ) = configureVpn(
        parseVpnConfiguration(addressHeader, dnsHeader, mtuHeader),
        runGeneration,
    )

    private fun parseVpnConfiguration(
        addressHeader: String?,
        dnsHeader: String?,
        mtuHeader: String?,
    ): VpnConfiguration {
        val addressParts = addressHeader?.split('/')
        if (addressParts?.size != 2) throw PermanentTunnelException("Gateway returned an invalid lease")
        val prefix = addressParts[1].toIntOrNull()
            ?: throw PermanentTunnelException("Gateway returned an invalid lease prefix")
        val mtu = mtuHeader?.toIntOrNull() ?: 1100
        if (prefix !in 0..32 || mtu !in 576..9000) {
            throw PermanentTunnelException("Gateway returned invalid network parameters")
        }
        if (parseIPv4Address(addressParts[0]) == null) {
            throw PermanentTunnelException("Gateway returned an invalid IPv4 address")
        }
        return VpnConfiguration(addressParts[0], prefix, dnsHeader.orEmpty(), mtu)
    }

    @Synchronized
    private fun configureVpn(configuration: VpnConfiguration, runGeneration: Long) {
        if (!isRunActive(runGeneration)) throw InterruptedException("Tunnel generation was replaced")
        if (descriptor.get() != null && vpnConfiguration == configuration && vpnReaderFailure.get() == null) return

        val sourceAddress = parseIPv4Address(configuration.address)
            ?: throw PermanentTunnelException("Gateway returned an invalid IPv4 address")
        val builder = Builder()
            .setSession(currentProfileName ?: "Porta")
            .setMtu(configuration.mtu)
            .addAddress(configuration.address, configuration.prefix)
            .addRoute("0.0.0.0", 0)
            .setBlocking(true)
        if (configuration.dns.isNotBlank()) builder.addDnsServer(configuration.dns)
        val vpn = builder.establish() ?: throw PermanentTunnelException("Android refused to establish the VPN")
        val previousReader = vpnReader
        vpnReader = null
        val previousVpn = descriptor.getAndSet(vpn)
        val nextInput = FileInputStream(vpn.fileDescriptor)
        val nextOutput = FileOutputStream(vpn.fileDescriptor)
        input = nextInput
        output = nextOutput
        vpnConfiguration = configuration
        vpnReaderFailure.set(null)
        failClosed.set(false)
        selectedNetwork.get()?.let { setUnderlyingNetworks(arrayOf(it)) }
        retireVpn(previousVpn, previousReader)
        if (previousReader?.isAlive == true) {
            val error = IOException("Previous VPN packet reader did not stop")
            vpnReaderFailure.set(error)
            throw error
        }
        if (previousVpn != null) outboundPackets.discardForRecovery()
        startVpnReader(sourceAddress)
    }

    private fun startVpnReader(sourceAddress: ByteArray) {
        val readerDescriptor = descriptor.get() ?: return
        val readerInput = input ?: return
        vpnReader = Thread({
            try {
                while (running.get() && descriptor.get() === readerDescriptor) {
                    val buffer = uplinkPacketPool.acquire()
                    val count = try {
                        readerInput.read(buffer)
                    } catch (error: Exception) {
                        uplinkPacketPool.recycle(buffer)
                        throw error
                    }
                    if (count < 0) {
                        uplinkPacketPool.recycle(buffer)
                        throw EOFException("VPN packet reader reached EOF")
                    }
                    if (count == 0) {
                        uplinkPacketPool.recycle(buffer)
                        continue
                    }
                    if (descriptor.get() !== readerDescriptor) {
                        uplinkPacketPool.recycle(buffer)
                        break
                    }
                    if (failClosed.get()) {
                        uplinkPacketPool.recycle(buffer)
                        continue
                    }
                    if (!isAssignedIPv4Packet(buffer, count, sourceAddress)) {
                        uplinkPacketPool.recycle(buffer)
                        continue
                    }
                    val packet = PacketBuffer.pooled(buffer, count, uplinkPacketPool)
                    if (!outboundPackets.offer(packet)) packet.release()
                }
            } catch (error: Exception) {
                if (!running.get() || descriptor.get() !== readerDescriptor) return@Thread
                synchronized(this) {
                    if (!running.get() || descriptor.get() !== readerDescriptor) return@Thread
                    vpnReaderFailure.set(error)
                    Log.w(TAG, "VPN packet reader stopped")
                    closeNativeDialer()
                    closeNativeSession()
                }
            }
        }, "porta-vpn-reader").also { it.start() }
    }

    @Suppress("DEPRECATION")
    private fun underlyingNetwork(): Network? {
        val connectivity = getSystemService(ConnectivityManager::class.java)
        preferredNetwork.getAndSet(null)?.let { network ->
            val capabilities = connectivity.getNetworkCapabilities(network)
            if (capabilities != null &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            ) {
                return network
            }
        }
        connectivity.activeNetwork?.let { network ->
            val capabilities = connectivity.getNetworkCapabilities(network)
            if (capabilities != null &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            ) {
                return network
            }
        }
        val candidates = connectivity.allNetworks.mapNotNull { network ->
            val capabilities = connectivity.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) ||
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            ) {
                return@mapNotNull null
            }
            network to capabilities
        }
        return candidates.firstOrNull { (_, capabilities) ->
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        }?.first ?: candidates.firstOrNull()?.first
    }

    private fun registerSelectedNetworkCallback(
        network: Network,
        attemptActive: AtomicBoolean,
        runGeneration: Long,
        onInvalidated: (String) -> Unit,
    ): SelectedNetworkCallbacks {
        val connectivity = getSystemService(ConnectivityManager::class.java)
        fun invalidate(reason: String) {
            if (attemptActive.compareAndSet(true, false) &&
                isRunActive(runGeneration) &&
                selectedNetwork.get() == network
            ) {
                onInvalidated(reason)
            }
        }
        val defaultCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(available: Network) {
                if (available == network) return
                val capabilities = connectivity.getNetworkCapabilities(available) ?: return
                if (capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                ) {
                    preferredNetwork.set(available)
                    invalidate("Underlying network changed")
                }
            }
        }
        val physicalCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onLost(lost: Network) {
                if (lost == network) invalidate("Underlying network was lost")
            }

            override fun onCapabilitiesChanged(
                changed: Network,
                capabilities: NetworkCapabilities,
            ) {
                if (changed == network &&
                    (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) ||
                        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN))
                ) {
                    invalidate("Underlying network is no longer usable")
                }
            }
        }
        connectivity.registerDefaultNetworkCallback(defaultCallback)
        try {
            connectivity.registerNetworkCallback(
                NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .build(),
                physicalCallback,
            )
        } catch (error: Exception) {
            connectivity.unregisterNetworkCallback(defaultCallback)
            throw error
        }
        return SelectedNetworkCallbacks(defaultCallback, physicalCallback)
    }

    private fun unregisterNetworkCallback(callbacks: SelectedNetworkCallbacks) {
        val connectivity = getSystemService(ConnectivityManager::class.java)
        for (callback in listOf(callbacks.defaultCallback, callbacks.physicalCallback)) {
            try {
                connectivity.unregisterNetworkCallback(callback)
            } catch (_: IllegalArgumentException) {
            }
        }
    }

    private fun cancelCurrentTransportAttempt() {
        closeNativeDialer()
        closeNativeSession()
    }

    private fun waitForRetry(reason: String, delayMillis: Long, runGeneration: Long): Boolean {
        val seconds = (delayMillis + 999L) / 1_000L
        synchronized(this) {
            if (!isRunActive(runGeneration)) return false
            logEvent("$reason; retrying in ${seconds}s")
            sendStatus("$reason; retrying in ${seconds}s")
            updateNotification("Reconnecting in ${seconds}s")
        }
        return try {
            Thread.sleep(delayMillis)
            isRunActive(runGeneration)
        } catch (_: InterruptedException) {
            isRunActive(runGeneration)
        }
    }

    private fun isRunActive(runGeneration: Long): Boolean =
        running.get() && generation.get() == runGeneration

    @Synchronized
    private fun updateConnectionStatus(value: String, runGeneration: Long) {
        if (!isRunActive(runGeneration)) return
        sendStatus(value)
        updateNotification(value)
    }

    @Synchronized
    private fun stopTunnel(message: String) {
        if (!running.getAndSet(false) && descriptor.get() == null) return
        generation.incrementAndGet()
        closeNativeDialer()
        closeNativeSession()
        worker?.interrupt()
        stopStatsWorker()
        closeVpn()
        selectedNetwork.set(null)
        preferredNetwork.set(null)
        currentProfileId = null
        currentProfileName = null
        currentSessionId = NO_SESSION
        currentSnapshot = TrafficSnapshot(
            totalDownloadedBytes = downloadedBytes.get(),
            totalUploadedBytes = uploadedBytes.get(),
        )
        resetConnectionDetailsState()
        logEvent(message)
        sendStatus(message)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    @Synchronized
    private fun holdVpnAfterTerminalFailure(runGeneration: Long, message: String): Boolean {
        if (!isRunActive(runGeneration) || descriptor.get() == null) return false
        closeNativeDialer()
        closeNativeSession()
        failClosed.set(true)
        outboundPackets.clear()
        selectedNetwork.set(null)
        preferredNetwork.set(null)
        worker = null
        sendStatus(message)
        updateNotification("Connection blocked")
        return true
    }

    @Synchronized
    private fun finishTunnel(runGeneration: Long, startId: Int, message: String) {
        if (generation.get() != runGeneration) return
        running.set(false)
        closeNativeDialer()
        closeNativeSession()
        stopStatsWorker()
        closeVpn()
        selectedNetwork.set(null)
        preferredNetwork.set(null)
        worker = null
        currentProfileId = null
        currentProfileName = null
        currentSessionId = NO_SESSION
        currentSnapshot = TrafficSnapshot(
            totalDownloadedBytes = downloadedBytes.get(),
            totalUploadedBytes = uploadedBytes.get(),
        )
        resetConnectionDetailsState()
        logEvent(message)
        sendStatus(message)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelfResult(startId)
    }

    private fun closeVpn() {
        val reader = vpnReader
        vpnReader = null
        val vpn = descriptor.getAndSet(null)
        retireVpn(vpn, reader)
        input = null
        output = null
        vpnConfiguration = null
        vpnReaderFailure.set(null)
        failClosed.set(false)
        outboundPackets.clear()
    }

    private fun retireVpn(vpn: ParcelFileDescriptor?, reader: Thread?) {
        try { vpn?.close() } catch (_: Exception) {}
        reader?.interrupt()
        if (reader != null && reader !== Thread.currentThread()) {
            try {
                reader.join(VPN_READER_STOP_TIMEOUT_MILLIS)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }
    }

    private fun closeNativeSession() {
        val session = nativeSession.getAndSet(null) ?: return
        try {
            session.close()
        } catch (_: Exception) {
        }
    }

    private fun closeNativeDialer() {
        nativeDialer.getAndSet(null)?.let(::closeDialer)
    }

    private fun closeDialer(dialer: Dialer) {
        try {
            dialer.close()
        } catch (_: Exception) {
        }
    }

    private fun sendStatus(value: String) {
        currentStatus = value
        sendBroadcast(
            Intent(ACTION_STATUS)
                .setPackage(packageName)
                .putExtra(EXTRA_STATUS, value)
                .putExtra(EXTRA_PROFILE_ID, currentProfileId)
                .putExtra(EXTRA_SESSION_ID, currentSessionId),
            STATUS_PERMISSION,
        )
    }

    private fun startStats(runGeneration: Long) {
        stopStatsWorker()
        statsWorker = Thread({
            var previousDownload = 0L
            var previousUpload = 0L
            var previousTime = System.nanoTime()
            while (isRunActive(runGeneration)) {
                try {
                    Thread.sleep(STATS_INTERVAL_MILLIS)
                } catch (_: InterruptedException) {
                    break
                }
                if (!isRunActive(runGeneration)) break
                val now = System.nanoTime()
                val download = downloadedBytes.get()
                val upload = uploadedBytes.get()
                val elapsedNanos = (now - previousTime).coerceAtLeast(1L)
                val snapshot = TrafficSnapshot(
                    downloadBytesPerSecond = (download - previousDownload) * NANOS_PER_SECOND / elapsedNanos,
                    uploadBytesPerSecond = (upload - previousUpload) * NANOS_PER_SECOND / elapsedNanos,
                    totalDownloadedBytes = download,
                    totalUploadedBytes = upload,
                )
                previousDownload = download
                previousUpload = upload
                previousTime = now
                if (!isRunActive(runGeneration)) break
                currentSnapshot = snapshot
                sendBroadcast(
                    Intent(ACTION_STATS)
                        .setPackage(packageName)
                        .putExtra(EXTRA_PROFILE_ID, currentProfileId)
                        .putExtra(EXTRA_SESSION_ID, runGeneration)
                        .putExtra(EXTRA_DOWNLOAD_BPS, snapshot.downloadBytesPerSecond)
                        .putExtra(EXTRA_UPLOAD_BPS, snapshot.uploadBytesPerSecond)
                        .putExtra(EXTRA_TOTAL_DOWNLOAD, snapshot.totalDownloadedBytes)
                        .putExtra(EXTRA_TOTAL_UPLOAD, snapshot.totalUploadedBytes),
                    STATUS_PERMISSION,
                )
            }
        }, "porta-traffic-stats").also { it.start() }
    }

    private fun stopStatsWorker() {
        val stats = statsWorker
        statsWorker = null
        stats?.interrupt()
        if (stats != null && stats !== Thread.currentThread()) {
            try {
                stats.join(STATS_STOP_TIMEOUT_MILLIS)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            }

        }
    }

    private fun logEvent(message: String) {
        Log.i(TAG, message)
        ClientLogStore(this).add(message)
    }

    private fun safeErrorMessage(error: Exception, token: String): String =
        diagnosticFailureDetail(error, token)

    private fun networkType(network: Network): String? {
        val connectivity = getSystemService(ConnectivityManager::class.java)
        val capabilities = connectivity.getNetworkCapabilities(network) ?: return null
        return when {
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_USB) -> "USB"
            else -> null
        }
    }

    private fun notification(text: String): Notification {
        val openApp = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val disconnect = PendingIntent.getService(
            this,
            1,
            Intent(this, TunnelService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(currentProfileName ?: "Porta")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_porta_status)
            .setOngoing(true)
            .setContentIntent(openApp)
            .addAction(
                Notification.Action.Builder(
                    Icon.createWithResource(this, R.drawable.ic_porta),
                    "Disconnect",
                    disconnect,
                ).build(),
            )
            .build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification(text))
    }

    private fun createNotificationChannel() {
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "VPN connection", NotificationManager.IMPORTANCE_LOW),
        )
    }

    companion object {
        const val ACTION_START = "dev.porta.android.START"
        const val ACTION_STOP = "dev.porta.android.STOP"
        const val ACTION_STATUS = "dev.porta.android.STATUS"
        const val ACTION_STATS = "dev.porta.android.STATS"
        const val EXTRA_SERVER = "server"
        const val EXTRA_TOKEN = "token"
        const val EXTRA_PROFILE_ID = "profile_id"
        const val EXTRA_PROFILE_NAME = "profile_name"
        const val EXTRA_SESSION_ID = "session_id"
        const val EXTRA_STATUS = "status"
        const val EXTRA_DOWNLOAD_BPS = "download_bps"
        const val EXTRA_UPLOAD_BPS = "upload_bps"
        const val EXTRA_TOTAL_DOWNLOAD = "total_download"
        const val EXTRA_TOTAL_UPLOAD = "total_upload"
        @Volatile private var currentStatus = "Disconnected"
        @Volatile private var currentProfileId: String? = null
        @Volatile private var currentProfileName: String? = null
        @Volatile private var currentSessionId = NO_SESSION
        @Volatile private var currentSnapshot = TrafficSnapshot()
        private val nextSessionId = AtomicLong()
        private const val CHANNEL_ID = "porta-vpn"
        private const val NOTIFICATION_ID = 1201
        private const val TAG = "Porta"
        private const val STABLE_CONNECTION_MILLIS = 30_000L
        private const val VPN_READER_STOP_TIMEOUT_MILLIS = 2_000L
        private const val NATIVE_SENDER_STOP_TIMEOUT_MILLIS = 2_000L
        private const val STATS_INTERVAL_MILLIS = 1_000L
        private const val STATS_STOP_TIMEOUT_MILLIS = 2_000L
        private const val NANOS_PER_SECOND = 1_000_000_000L
        private const val NO_SESSION = 0L
        private const val MAX_VPN_PACKET_SIZE = 9_000
        private const val STATUS_PERMISSION = "dev.porta.android.permission.STATUS"

        fun currentStatus(): String = currentStatus
        fun currentProfileId(): String? = currentProfileId
        internal fun currentSessionId(): Long = currentSessionId
        internal fun currentTrafficSnapshot(): TrafficSnapshot = currentSnapshot
    }

    private data class VpnConfiguration(
        val address: String,
        val prefix: Int,
        val dns: String,
        val mtu: Int,
    )

    private data class SelectedNetworkCallbacks(
        val defaultCallback: ConnectivityManager.NetworkCallback,
        val physicalCallback: ConnectivityManager.NetworkCallback,
    )

    private class PermanentTunnelException(
        message: String,
        cause: Throwable? = null,
    ) : Exception(message, cause)
}

internal data class TrafficSnapshot(
    val downloadBytesPerSecond: Long = 0,
    val uploadBytesPerSecond: Long = 0,
    val totalDownloadedBytes: Long = 0,
    val totalUploadedBytes: Long = 0,
)

internal fun gatewayHost(server: String): String? = try {
    URI(server).host?.removePrefix("[")?.removeSuffix("]")?.takeIf { it.isNotBlank() }
} catch (_: Exception) {
    null
}

internal fun parseIPv4Address(value: String): ByteArray? {
    val parts = value.split('.')
    if (parts.size != 4) return null
    val result = ByteArray(4)
    for (index in parts.indices) {
        val part = parts[index]
        if (part.isEmpty() || part.length > 3 || part.any { it !in '0'..'9' } ||
            (part.length > 1 && part[0] == '0')
        ) return null
        val octet = part.toIntOrNull() ?: return null
        if (octet !in 0..255) return null
        result[index] = octet.toByte()
    }
    return result
}

internal fun isAssignedIPv4Packet(packet: ByteArray, length: Int, sourceAddress: ByteArray): Boolean {
    if (length < 20 || length > packet.size || sourceAddress.size != 4 ||
        (packet[0].toInt() ushr 4) != 4
    ) return false
    val headerLength = (packet[0].toInt() and 0x0f) * 4
    val totalLength = ((packet[2].toInt() and 0xff) shl 8) or (packet[3].toInt() and 0xff)
    if (headerLength < 20 || headerLength > length || totalLength != length) return false
    for (index in sourceAddress.indices) {
        if (packet[12 + index] != sourceAddress[index]) return false
    }
    return true
}
