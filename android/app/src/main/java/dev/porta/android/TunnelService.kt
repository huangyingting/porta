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
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import portamobile.Portamobile
import portamobile.Dialer
import portamobile.Protector
import portamobile.Session
import okhttp3.Call
import okhttp3.ConnectionPool
import okhttp3.Dns
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody
import okio.BufferedSink
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.EOFException
import java.io.IOException
import java.net.URI
import java.net.UnknownHostException
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import java.util.UUID

class TunnelService : VpnService() {
    private val running = AtomicBoolean(false)
    private val generation = AtomicLong(0)
    private val uploadedBytes = AtomicLong(0)
    private val downloadedBytes = AtomicLong(0)
    private val descriptor = AtomicReference<ParcelFileDescriptor?>()
    private val vpnReaderFailure = AtomicReference<Exception?>()
    private val selectedNetwork = AtomicReference<Network?>()
    private val outboundPackets = ArrayBlockingQueue<ByteArray>(512)
    private val http2Calls = ConcurrentHashMap.newKeySet<Call>()
    private val http2LaneQueues = AtomicReference<List<ArrayBlockingQueue<ByteArray>>?>()
    private val queueRoutingLock = Any()
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
        val clientId = try {
            androidDeviceIdentity(this)
        } catch (_: DeviceIdentityUnavailableException) {
            stopTunnel(getString(R.string.device_identity_unavailable))
            return START_NOT_STICKY
        }
        currentProfileId = profileId.ifBlank { server }
        currentProfileName = profileLabel.ifBlank { profileName(server) }
        currentSessionId = runGeneration
        uploadedBytes.set(0)
        downloadedBytes.set(0)
        currentSnapshot = TrafficSnapshot()
        resetConnectionDetailsState()
        logEvent("Porta ${Portamobile.version()}; protocol ${PacketFraming.VERSION}")
        logEvent("Device ID: ${redactDiagnosticMessage(clientId, token)} (Android supplied)")
        logEvent("Connecting ${currentProfileName} to ${redactDiagnosticMessage(server, token)}")

        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification("Connecting"), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification("Connecting"))
        }
        sendStatus("Connecting")
        startStats(runGeneration)
        worker = Thread(
            { runTunnel(server, token, clientId, runGeneration, startId) },
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
        clientId: String,
        runGeneration: Long,
        startId: Int,
    ) {
        val client = OkHttpClient.Builder()
            .dns(object : Dns {
                override fun lookup(hostname: String) = selectedNetwork.get()
                    ?.getAllByName(hostname)
                    ?.toList()
                    ?: underlyingNetwork()
                    ?.getAllByName(hostname)
                    ?.toList()
                    ?: throw UnknownHostException("No underlying network is available")
            })
            .socketFactory(ProtectedSocketFactory(this) {
                selectedNetwork.get() ?: underlyingNetwork()
            })
            .protocols(listOf(Protocol.HTTP_2, Protocol.HTTP_1_1))
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.MILLISECONDS)
            .writeTimeout(0, TimeUnit.MILLISECONDS)
            .pingInterval(20, TimeUnit.SECONDS)
            .retryOnConnectionFailure(false)
            .build()
        val backoff = ReconnectBackoff(clientId)
        var finalStatus = "Disconnected"
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
                    setUnderlyingNetworks(arrayOf(network))
                    beginConnectionAttempt(runGeneration)
                }
                val selectedNetworkType = networkType(network)
                val attemptActive = AtomicBoolean(true)
                val vpnReady = CountDownLatch(1)
                var attemptConnectedAt = 0L
                try {
                    val reconnecting = descriptor.get() != null
                    updateConnectionStatus(if (reconnecting) "Reconnecting" else "Connecting", runGeneration)
                    try {
                        logEvent(formatAttemptEvent("HTTP/3 MASQUE", selectedNetworkType))
                        connectNativeOnce(
                            server,
                            token,
                            clientId,
                            network,
                            attemptActive,
                            attemptToken,
                            selectedNetworkType,
                            runGeneration,
                        ) {
                            attemptConnectedAt = System.currentTimeMillis()
                        }
                    } catch (error: NativeTransportUnavailableException) {
                        if (!isRunActive(runGeneration)) break
                        Log.i(TAG, "HTTP/3 MASQUE unavailable; falling back to HTTP/2")
                        logEvent(
                            "HTTP/3 unavailable: ${safeErrorMessage(error, token)}; " +
                                "trying encrypted HTTP/2 fallback",
                        )
                        connectHttp2Once(
                            client,
                            server,
                            token,
                            clientId,
                            attemptActive,
                            vpnReady,
                            attemptToken,
                            selectedNetworkType,
                            runGeneration,
                        ) {
                            attemptConnectedAt = System.currentTimeMillis()
                        }
                    }
                } catch (error: PermanentTunnelException) {
                    if (!isRunActive(runGeneration)) break
                    finalStatus = "Connection rejected: ${safeErrorMessage(error, token)}"
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
                    client.connectionPool.evictAll()
                    synchronized(this) {
                        if (isRunActive(runGeneration)) selectedNetwork.set(null)
                    }
                    if (!waitForRetry("Connection lost", backoff.nextDelayMillis(), runGeneration)) break
                } finally {
                    attemptActive.set(false)
                    vpnReady.countDown()
                }
            }
        } finally {
            client.dispatcher.executorService.shutdown()
            client.connectionPool.evictAll()
            finishTunnel(runGeneration, startId, finalStatus)
        }
    }

    private fun connectNativeOnce(
        server: String,
        token: String,
        clientId: String,
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
                    return "configuration: Android refused to protect the UDP socket"
                }
                return try {
                    ParcelFileDescriptor.fromFd(fd).use { socket ->
                        network.bindSocket(socket.fileDescriptor)
                    }
                    ""
                } catch (error: IOException) {
                    "transport unavailable: could not bind UDP socket to the selected network"
                }
            }
        }
        val dialer = Portamobile.newDialer()
        val readerFailureBeforeDial = synchronized(this) {
            if (!isRunActive(runGeneration)) {
                dialer.close()
                throw InterruptedException("Tunnel generation was replaced")
            }
            if (!nativeDialer.compareAndSet(null, dialer)) {
                dialer.close()
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
                    session = dialer.dial(server, token, clientId, remoteAddress, protector)
                    connected = true
                    break
                } catch (error: Exception) {
                    if (!isRunActive(runGeneration)) throw InterruptedException("Tunnel stopped")
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
                dialer.close()
            }
        }
        val activeSession = session
            ?: throw NativeTransportUnavailableException(
                unavailable?.message ?: "HTTP/3 MASQUE is unavailable",
            )
        synchronized(this) {
            if (!isRunActive(runGeneration) || !nativeSession.compareAndSet(null, activeSession)) {
                nativeDialer.compareAndSet(dialer, null)
                dialer.close()
                activeSession.close()
                throw IOException("Native tunnel was stopped or replaced")
            }
        }

        val senderError = AtomicReference<Exception?>()
        val sender = Thread({
            try {
                while (isRunActive(runGeneration) && attemptActive.get()) {
                    val packet = outboundPackets.poll(1, TimeUnit.SECONDS) ?: continue
                    if (!isRunActive(runGeneration) || !attemptActive.get()) break
                    activeSession.send(packet)
                    if (isRunActive(runGeneration)) {
                        uploadedBytes.addAndGet(packet.size.toLong())
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
        }, "porta-http3-upload")

        try {
            configureVpn(
                activeSession.address(),
                activeSession.dns(),
                activeSession.mtu().toString(),
                runGeneration,
            )
            val details = ConnectionTelemetry(
                transport = "HTTP/3 MASQUE",
                mtu = activeSession.mtu().toInt(),
                automaticMtu = activeSession.automaticMTU(),
                mtuCeiling = activeSession.maximumMTU().toInt().takeIf { it > 0 },
                address = activeSession.address(),
                dns = activeSession.dns(),
                deliveryMode = when (activeSession.packetDeliveryMode()) {
                    "datagram" -> "datagrams"
                    "capsule" -> "capsules"
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
            updateConnectionStatus("Connected over HTTP/3 MASQUE", runGeneration)
            sender.start()
            while (isRunActive(runGeneration) && attemptActive.get()) {
                val packet = activeSession.receive()
                if (!isRunActive(runGeneration) || !attemptActive.get()) break
                tunnelOutput.write(packet)
                if (isRunActive(runGeneration)) {
                    downloadedBytes.addAndGet(packet.size.toLong())
                }
            }
            if (isRunActive(runGeneration)) throw IOException("Gateway closed the native tunnel")
        } catch (error: Exception) {
            val uploadError = senderError.get()
            if (uploadError != null) throw IOException("Native tunnel upload stopped", uploadError)
            if (isRunActive(runGeneration)) throw error
        } finally {
            attemptActive.set(false)
            nativeDialer.compareAndSet(dialer, null)
            dialer.close()
            nativeSession.compareAndSet(activeSession, null)
            try {
                activeSession.close()
            } catch (_: Exception) {
            }
            sender.interrupt()
            if (sender.isAlive && sender !== Thread.currentThread()) {
                try {
                    sender.join(REQUEST_WRITER_STOP_TIMEOUT_MILLIS)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
            }
        }
    }

    private fun connectHttp2Once(
        client: OkHttpClient,
        server: String,
        token: String,
        clientId: String,
        attemptActive: AtomicBoolean,
        vpnReady: CountDownLatch,
        attemptToken: ConnectionAttemptToken,
        selectedNetworkType: String?,
        runGeneration: Long,
        onConnected: () -> Unit,
    ) {
        val attemptStartedAt = System.nanoTime()
        val sessionId = UUID.randomUUID().toString().replace("-", "")
        val laneQueues = List(HTTP2_LANE_COUNT) { ArrayBlockingQueue<ByteArray>(128) }
        val laneClients = List(HTTP2_LANE_COUNT) {
            client.newBuilder().connectionPool(ConnectionPool()).build()
        }
        val laneReady = CountDownLatch(HTTP2_LANE_COUNT)
        val lanesActive = AtomicBoolean(true)
        val uploadReady = CountDownLatch(1)
        val vpnConfigured = CountDownLatch(1)
        val expectedConfiguration = AtomicReference<VpnConfiguration?>()
        val errors = LinkedBlockingQueue<Exception>()
        val downstreamPackets = ArrayBlockingQueue<ByteArray>(512)
        val sessionCalls = ConcurrentHashMap.newKeySet<Call>()
        val laneThreads = laneClients.mapIndexed { laneIndex, laneClient ->
            Thread({
                runHttp2Lane(
                    laneClient,
                    server,
                    token,
                    clientId,
                    sessionId,
                    laneIndex,
                    laneQueues[laneIndex],
                    downstreamPackets,
                    lanesActive,
                    uploadReady,
                    vpnConfigured,
                    laneReady,
                    expectedConfiguration,
                    errors,
                    sessionCalls,
                    runGeneration,
                )
            }, "porta-http2-lane-$laneIndex").also { it.start() }
        }
        var downstreamWriter: Thread? = null
        try {
            val deadline = System.nanoTime() +
                TimeUnit.SECONDS.toNanos(HTTP2_LANE_CONNECT_TIMEOUT_SECONDS)
            while (laneReady.count > 0 && isRunActive(runGeneration) && lanesActive.get()) {
                errors.poll(100, TimeUnit.MILLISECONDS)?.let { throw it }
                if (System.nanoTime() >= deadline) {
                    throw IOException("Timed out establishing all HTTP/2 fallback lanes")
                }
            }
            errors.poll()?.let { throw it }
            if (!isRunActive(runGeneration)) return
            if (!lanesActive.get()) throw IOException("HTTP/2 fallback lane stopped during setup")
            val tunnelOutput = output ?: throw IOException("VPN output is unavailable")
            synchronized(queueRoutingLock) {
                if (http2LaneQueues.get() != null) {
                    throw IOException("Another HTTP/2 fallback session is active")
                }
                http2LaneQueues.set(laneQueues)
                while (true) {
                    val packet = outboundPackets.poll() ?: break
                    offerLatest(laneQueues[http2PacketLane(packet, laneQueues.size)], packet)
                }
            }
            vpnReady.countDown()
            uploadReady.countDown()
            val configuration = expectedConfiguration.get()
                ?: throw IOException("HTTP/2 fallback did not return a VPN lease")
            val details = ConnectionTelemetry(
                transport = "multi-lane HTTP/2",
                mtu = configuration.mtu,
                automaticMtu = false,
                address = "${configuration.address}/${configuration.prefix}",
                dns = configuration.dns,
                deliveryMode = "$HTTP2_LANE_COUNT lanes",
                networkType = selectedNetworkType,
                setupDurationMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - attemptStartedAt),
                appVersion = Portamobile.version(),
                protocolVersion = PacketFraming.VERSION,
            )
            if (!publishConnectionDetails(attemptToken, details.toConnectionDetails())) {
                throw InterruptedException("HTTP/2 fallback was replaced")
            }
            onConnected()
            formatConnectedEvents(details).forEach(::logEvent)
            updateConnectionStatus("Connected over multi-lane HTTP/2", runGeneration)
            downstreamWriter = Thread({
                try {
                    while (isRunActive(runGeneration) && lanesActive.get()) {
                        val packet = downstreamPackets.poll(1, TimeUnit.SECONDS) ?: continue
                        if (!isRunActive(runGeneration) || !lanesActive.get()) break
                        tunnelOutput.write(packet)
                        downloadedBytes.addAndGet(packet.size.toLong())
                    }
                } catch (error: Exception) {
                    if (isRunActive(runGeneration) && lanesActive.get()) errors.offer(error)
                }
            }, "porta-http2-download").also { it.start() }
            while (isRunActive(runGeneration) && lanesActive.get()) {
                errors.poll(1, TimeUnit.SECONDS)?.let { throw it }
            }
            errors.poll()?.let { throw it }
        } finally {
            synchronized(this) {
                lanesActive.set(false)
                sessionCalls.forEach(Call::cancel)
            }
            uploadReady.countDown()
            vpnConfigured.countDown()
            laneThreads.forEach {
                it.interrupt()
                if (it.isAlive && it !== Thread.currentThread()) {
                    try {
                        it.join(REQUEST_WRITER_STOP_TIMEOUT_MILLIS)
                    } catch (_: InterruptedException) {
                        Thread.currentThread().interrupt()
                    }
                }
            }
            downstreamWriter?.interrupt()
            if (downstreamWriter?.isAlive == true && downstreamWriter !== Thread.currentThread()) {
                try {
                    downstreamWriter.join(REQUEST_WRITER_STOP_TIMEOUT_MILLIS)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
            }
            laneClients.forEach { it.connectionPool.evictAll() }
            synchronized(queueRoutingLock) {
                if (http2LaneQueues.get() === laneQueues) {
                    http2LaneQueues.set(null)
                    if (isRunActive(runGeneration)) {
                        laneQueues.forEach { queue ->
                            while (true) {
                                val packet = queue.poll() ?: break
                                offerLatest(outboundPackets, packet)
                            }
                        }
                    } else {
                        laneQueues.forEach { it.clear() }
                    }
                }
            }
        }
    }

    private fun runHttp2Lane(
        client: OkHttpClient,
        server: String,
        token: String,
        clientId: String,
        sessionId: String,
        laneIndex: Int,
        outboundQueue: ArrayBlockingQueue<ByteArray>,
        downstreamPackets: ArrayBlockingQueue<ByteArray>,
        active: AtomicBoolean,
        uploadReady: CountDownLatch,
        vpnConfigured: CountDownLatch,
        laneReady: CountDownLatch,
        expectedConfiguration: AtomicReference<VpnConfiguration?>,
        errors: LinkedBlockingQueue<Exception>,
        sessionCalls: MutableSet<Call>,
        runGeneration: Long,
    ) {
        val attemptCall = AtomicReference<Call?>()
        val requestBody = TunRequestBody(active, uploadReady, attemptCall, outboundQueue, runGeneration)
        val request = Request.Builder()
            .url(server.trimEnd('/') + "/v1/tunnel")
            .header("Authorization", "Bearer $token")
            .header("X-Porta-Version", PacketFraming.VERSION)
            .header("X-Porta-Client-ID", clientId)
            .header(HEADER_LANE_SESSION, sessionId)
            .header(HEADER_LANE_INDEX, laneIndex.toString())
            .header(HEADER_LANE_COUNT, HTTP2_LANE_COUNT.toString())
            .post(requestBody)
            .build()
        val activeCall = client.newCall(request)
        attemptCall.set(activeCall)
        synchronized(this) {
            if (!isRunActive(runGeneration) || !active.get()) {
                activeCall.cancel()
                return
            }
            http2Calls.add(activeCall)
            sessionCalls.add(activeCall)
        }
        try {
            activeCall.execute().use { response ->
                if (!response.isSuccessful) {
                    if (response.code == 426) {
                        val minimum = response.header(HEADER_PROTOCOL_MIN_VERSION).orEmpty()
                        val maximum = response.header(HEADER_PROTOCOL_MAX_VERSION).orEmpty()
                        val supported = if (maximum.isNotEmpty() && maximum != minimum) {
                            "$minimum-$maximum"
                        } else {
                            minimum.ifEmpty { "an incompatible version" }
                        }
                        throw PermanentTunnelException(
                            "Gateway requires Porta protocol $supported; client uses ${PacketFraming.VERSION}",
                        )
                    }
                    val message = "Gateway returned HTTP ${response.code} for HTTP/2 lane $laneIndex"
                    if (response.code in 400..499 && response.code !in RETRYABLE_HTTP_CODES) {
                        throw PermanentTunnelException(message)
                    }
                    throw IOException(message)
                }
                if (response.protocol != Protocol.HTTP_2) {
                    throw PermanentTunnelException("Gateway did not negotiate HTTP/2")
                }
                if (response.header(HEADER_PROTOCOL_VERSION) != PacketFraming.VERSION) {
                    throw PermanentTunnelException("Gateway selected an incompatible Porta protocol")
                }
                if (response.header(HEADER_LANE_SESSION) != sessionId ||
                    response.header(HEADER_LANE_INDEX) != laneIndex.toString() ||
                    response.header(HEADER_LANE_COUNT) != HTTP2_LANE_COUNT.toString()
                ) {
                    throw PermanentTunnelException("Gateway rejected HTTP/2 lane negotiation")
                }

                val configuration = parseVpnConfiguration(
                    response.header("X-Porta-Address"),
                    response.header("X-Porta-DNS"),
                    response.header("X-Porta-MTU"),
                )
                if (expectedConfiguration.compareAndSet(null, configuration)) {
                    configureVpn(configuration, runGeneration)
                    vpnConfigured.countDown()
                } else {
                    if (expectedConfiguration.get() != configuration) {
                        throw PermanentTunnelException("HTTP/2 lanes returned different VPN leases")
                    }
                    if (!vpnConfigured.await(HTTP2_LANE_CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                        throw IOException("Timed out configuring the VPN interface")
                    }
                }
                laneReady.countDown()
                val responseBody = response.body ?: throw IOException("Gateway returned no response stream")
                val source = responseBody.source()
                while (isRunActive(runGeneration) && active.get()) {
                    val packet = PacketFraming.read(source) ?: continue
                    if (!downstreamPackets.offer(packet)) {
                        downstreamPackets.poll()
                        downstreamPackets.offer(packet)
                    }
                }
                if (isRunActive(runGeneration) && active.get()) {
                    throw IOException("HTTP/2 lane $laneIndex closed")
                }
            }
        } catch (error: Exception) {
            if (isRunActive(runGeneration) && active.get()) errors.offer(error)
        } finally {
            activeCall.cancel()
            requestBody.stop()
            http2Calls.remove(activeCall)
            sessionCalls.remove(activeCall)
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
        closeVpn()

        val builder = Builder()
            .setSession(currentProfileName ?: "Porta")
            .setMtu(configuration.mtu)
            .addAddress(configuration.address, configuration.prefix)
            .addRoute("0.0.0.0", 0)
            .setBlocking(true)
        if (configuration.dns.isNotBlank()) builder.addDnsServer(configuration.dns)
        val vpn = builder.establish() ?: throw PermanentTunnelException("Android refused to establish the VPN")
        descriptor.set(vpn)
        input = FileInputStream(vpn.fileDescriptor)
        output = FileOutputStream(vpn.fileDescriptor)
        vpnConfiguration = configuration
        selectedNetwork.get()?.let { setUnderlyingNetworks(arrayOf(it)) }
        val sourceAddress = parseIPv4Address(configuration.address)
            ?: throw PermanentTunnelException("Gateway returned an invalid IPv4 address")
        startVpnReader(sourceAddress)
    }

    private fun startVpnReader(sourceAddress: ByteArray) {
        val readerDescriptor = descriptor.get() ?: return
        val readerInput = input ?: return
        vpnReader = Thread({
            val buffer = ByteArray(65_535)
            try {
                while (running.get() && descriptor.get() === readerDescriptor) {
                    val count = readerInput.read(buffer)
                    if (count < 0) throw EOFException("VPN packet reader reached EOF")
                    if (count == 0) continue
                    if (descriptor.get() !== readerDescriptor) break
                    if (!isAssignedIPv4Packet(buffer, count, sourceAddress)) continue
                    val packet = buffer.copyOf(count)
                    synchronized(queueRoutingLock) {
                        val lanes = http2LaneQueues.get()
                        val queue = if (lanes == null) {
                            outboundPackets
                        } else {
                            lanes[http2PacketLane(packet, lanes.size)]
                        }
                        offerLatest(queue, packet)
                    }
                }
            } catch (error: Exception) {
                if (!running.get() || descriptor.get() !== readerDescriptor) return@Thread
                synchronized(this) {
                    if (!running.get() || descriptor.get() !== readerDescriptor) return@Thread
                    vpnReaderFailure.set(error)
                    Log.w(TAG, "VPN packet reader stopped")
                    http2Calls.forEach(Call::cancel)
                    closeNativeDialer()
                    closeNativeSession()
                }
            }
        }, "porta-vpn-reader").also { it.start() }
    }

    private fun offerLatest(queue: ArrayBlockingQueue<ByteArray>, packet: ByteArray) {
        if (!queue.offer(packet)) {
            queue.poll()
            queue.offer(packet)
        }
    }

    @Suppress("DEPRECATION")
    private fun underlyingNetwork(): Network? {
        val connectivity = getSystemService(ConnectivityManager::class.java)
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

    private inner class TunRequestBody(
        private val active: AtomicBoolean,
        private val ready: CountDownLatch,
        private val ownerCall: AtomicReference<Call?>,
        private val outboundQueue: ArrayBlockingQueue<ByteArray>,
        private val runGeneration: Long,
    ) : RequestBody() {
        private val writer = AtomicReference<Thread?>()

        override fun contentType() = PacketFraming.CONTENT_TYPE.toMediaType()
        override fun isDuplex() = true

        override fun writeTo(sink: BufferedSink) {
            PacketFraming.write(sink, byteArrayOf())
            val thread = Thread({
                try {
                    ready.await()
                    val batch = ArrayList<ByteArray>(HTTP2_UPLOAD_BATCH_SIZE)
                    while (isRunActive(runGeneration) && active.get()) {
                        val packet = outboundQueue.poll(1, TimeUnit.SECONDS) ?: continue
                        if (!isRunActive(runGeneration) || !active.get()) break
                        batch.clear()
                        batch.add(packet)
                        outboundQueue.drainTo(batch, HTTP2_UPLOAD_BATCH_SIZE - 1)
                        val bytes = PacketFraming.writeBatch(sink, batch)
                        if (isRunActive(runGeneration)) {
                            uploadedBytes.addAndGet(bytes)
                        }
                    }
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                } catch (_: Exception) {
                    if (running.get() && active.get()) {
                        ownerCall.get()?.cancel()
                    }
                } finally {
                    try {
                        sink.close()
                    } catch (_: IOException) {
                    }
                }
            }, "porta-http2-upload")
            check(writer.compareAndSet(null, thread)) { "duplex request body was written more than once" }
            thread.start()
        }

        fun stop() {
            active.set(false)
            ready.countDown()
            val thread = writer.getAndSet(null)
            thread?.interrupt()
            if (thread != null && thread !== Thread.currentThread()) {
                try {
                    thread.join(REQUEST_WRITER_STOP_TIMEOUT_MILLIS)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
            }
        }
    }

    @Synchronized
    private fun stopTunnel(message: String) {
        if (!running.getAndSet(false) && descriptor.get() == null && http2Calls.isEmpty()) return
        generation.incrementAndGet()
        http2Calls.forEach(Call::cancel)
        closeNativeDialer()
        closeNativeSession()
        worker?.interrupt()
        stopStatsWorker()
        closeVpn()
        selectedNetwork.set(null)
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
    private fun finishTunnel(runGeneration: Long, startId: Int, message: String) {
        if (generation.get() != runGeneration) return
        running.set(false)
        http2Calls.forEach(Call::cancel)
        closeNativeDialer()
        closeNativeSession()
        stopStatsWorker()
        closeVpn()
        selectedNetwork.set(null)
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
        try { vpn?.close() } catch (_: Exception) {}
        reader?.interrupt()
        if (reader != null && reader !== Thread.currentThread()) {
            try {
                reader.join(VPN_READER_STOP_TIMEOUT_MILLIS)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }
        input = null
        output = null
        vpnConfiguration = null
        vpnReaderFailure.set(null)
        outboundPackets.clear()
    }

    private fun closeNativeSession() {
        val session = nativeSession.getAndSet(null) ?: return
        try {
            session.close()
        } catch (_: Exception) {
        }
    }

    private fun closeNativeDialer() {
        nativeDialer.getAndSet(null)?.close()
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
        private const val REQUEST_WRITER_STOP_TIMEOUT_MILLIS = 2_000L
        private const val STATS_INTERVAL_MILLIS = 1_000L
        private const val STATS_STOP_TIMEOUT_MILLIS = 2_000L
        private const val NANOS_PER_SECOND = 1_000_000_000L
        private const val NO_SESSION = 0L
        private const val HTTP2_LANE_COUNT = 4
        private const val HTTP2_UPLOAD_BATCH_SIZE = 16
        private const val HTTP2_LANE_CONNECT_TIMEOUT_SECONDS = 20L
        private const val HEADER_PROTOCOL_VERSION = "X-Porta-Version"
        private const val HEADER_PROTOCOL_MIN_VERSION = "X-Porta-Min-Version"
        private const val HEADER_PROTOCOL_MAX_VERSION = "X-Porta-Max-Version"
        private const val HEADER_LANE_SESSION = "X-Porta-Lane-Session"
        private const val HEADER_LANE_INDEX = "X-Porta-Lane"
        private const val HEADER_LANE_COUNT = "X-Porta-Lanes"
        private const val STATUS_PERMISSION = "dev.porta.android.permission.STATUS"
        private val RETRYABLE_HTTP_CODES = setOf(408, 425, 429)

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

    private class PermanentTunnelException(message: String) : Exception(message)
    private class NativeTransportUnavailableException(message: String) : Exception(message)
}

internal data class TrafficSnapshot(
    val downloadBytesPerSecond: Long = 0,
    val uploadBytesPerSecond: Long = 0,
    val totalDownloadedBytes: Long = 0,
    val totalUploadedBytes: Long = 0,
)

internal fun http2PacketLane(packet: ByteArray, laneCount: Int): Int {
    if (laneCount <= 1 || packet.size < 20 || (packet[0].toInt() ushr 4) != 4) return 0
    val headerLength = (packet[0].toInt() and 0x0f) * 4
    if (headerLength < 20 || headerLength > packet.size) return 0
    val protocol = packet[9].toInt() and 0xff
    val fragmented = (packet[6].toInt() and 0x3f) != 0 || packet[7] != 0.toByte()
    val hasPorts = !fragmented && (protocol == 6 || protocol == 17) &&
        packet.size >= headerLength + 4
    if (hasPorts) {
        val sourcePort = ((packet[headerLength].toInt() and 0xff) shl 8) or
            (packet[headerLength + 1].toInt() and 0xff)
        val destinationPort = ((packet[headerLength + 2].toInt() and 0xff) shl 8) or
            (packet[headerLength + 3].toInt() and 0xff)
        if (sourcePort == 53 || destinationPort == 53) return 0
    }
    var hash = 0x811c9dc5L
    hash = (hash xor protocol.toLong()) * 0x01000193L and 0xffffffffL
    for (index in 12 until 20) {
        hash = (hash xor (packet[index].toLong() and 0xff)) * 0x01000193L and 0xffffffffL
    }
    if (hasPorts) {
        for (index in headerLength until headerLength + 4) {
            hash = (hash xor (packet[index].toLong() and 0xff)) * 0x01000193L and 0xffffffffL
        }
    }
    return 1 + (hash % (laneCount - 1)).toInt()
}

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
