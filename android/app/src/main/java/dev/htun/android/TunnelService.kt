package dev.htun.android

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
import htunmobile.Htunmobile
import htunmobile.Dialer
import htunmobile.Protector
import htunmobile.Session
import okhttp3.Call
import okhttp3.Dns
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody
import okio.BufferedSink
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.URI
import java.net.UnknownHostException
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

class TunnelService : VpnService() {
    private val running = AtomicBoolean(false)
    private val generation = AtomicLong(0)
    private val uploadedBytes = AtomicLong(0)
    private val downloadedBytes = AtomicLong(0)
    private val descriptor = AtomicReference<ParcelFileDescriptor?>()
    private val selectedNetwork = AtomicReference<Network?>()
    private val outboundPackets = ArrayBlockingQueue<ByteArray>(256)
    @Volatile private var call: Call? = null
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
        val runGeneration = generation.incrementAndGet()

        val server = intent.getStringExtra(EXTRA_SERVER).orEmpty()
        val token = intent.getStringExtra(EXTRA_TOKEN).orEmpty()
        val clientId = intent.getStringExtra(EXTRA_CLIENT_ID).orEmpty()
        val profileId = intent.getStringExtra(EXTRA_PROFILE_ID).orEmpty()
        val profileLabel = intent.getStringExtra(EXTRA_PROFILE_NAME).orEmpty()
        if (!validConfiguration(server, token, clientId)) {
            logEvent("Connection rejected: invalid profile configuration")
            stopTunnel("Invalid tunnel configuration")
            return START_NOT_STICKY
        }
        currentProfileId = profileId.ifBlank { server }
        currentProfileName = profileLabel.ifBlank { profileName(server) }
        currentSessionId = runGeneration
        uploadedBytes.set(0)
        downloadedBytes.set(0)
        currentSnapshot = TrafficSnapshot()
        logEvent("Connecting ${currentProfileName} to ${gatewayHost(server) ?: server}")

        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification("Connecting"), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification("Connecting"))
        }
        sendStatus("Connecting")
        startStats(runGeneration)
        worker = Thread(
            { runTunnel(server, token, clientId, runGeneration, startId) },
            "htun-transport",
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
                selectedNetwork.set(network)
                setUnderlyingNetworks(arrayOf(network))
                val attemptActive = AtomicBoolean(true)
                val vpnReady = CountDownLatch(1)
                var attemptConnectedAt = 0L
                try {
                    val reconnecting = descriptor.get() != null
                    sendStatus(if (reconnecting) "Reconnecting" else "Connecting")
                    updateNotification(if (reconnecting) "Reconnecting" else "Connecting")
                    try {
                        logEvent("Trying HTTP/3 MASQUE")
                        connectNativeOnce(
                            server,
                            token,
                            clientId,
                            network,
                            attemptActive,
                            runGeneration,
                        ) {
                            attemptConnectedAt = System.currentTimeMillis()
                        }
                    } catch (error: NativeTransportUnavailableException) {
                        if (!isRunActive(runGeneration)) break
                        Log.i(TAG, "HTTP/3 MASQUE unavailable; falling back to HTTP/2")
                        logEvent("HTTP/3 unavailable; trying encrypted HTTP/2 fallback")
                        connectLegacyOnce(
                            client,
                            server,
                            token,
                            clientId,
                            attemptActive,
                            vpnReady,
                            runGeneration,
                        ) {
                            attemptConnectedAt = System.currentTimeMillis()
                        }
                    }
                } catch (error: PermanentTunnelException) {
                    finalStatus = error.message ?: "Connection rejected"
                    Log.w(TAG, "Tunnel rejected: ${error.message}")
                    logEvent("Connection rejected: ${safeErrorMessage(error, token)}")
                    break
                } catch (error: Exception) {
                    if (!isRunActive(runGeneration)) break
                    Log.w(TAG, "Tunnel interrupted", error)
                    logEvent("Connection interrupted: ${safeErrorMessage(error, token)}")
                    if (attemptConnectedAt != 0L &&
                        System.currentTimeMillis() - attemptConnectedAt >= STABLE_CONNECTION_MILLIS
                    ) {
                        backoff.reset()
                    }
                    client.connectionPool.evictAll()
                    selectedNetwork.set(null)
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
        runGeneration: Long,
        onConnected: () -> Unit,
    ) {
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
        val dialer = Htunmobile.newDialer()
        if (!nativeDialer.compareAndSet(null, dialer)) {
            dialer.close()
            throw IOException("Another native connection attempt is active")
        }
        var session: Session? = null
        var unavailable: Exception? = null
        var connected = false
        try {
            for (remoteAddress in remoteAddresses) {
                try {
                    session = dialer.dial(server, token, clientId, remoteAddress, protector)
                    connected = true
                    break
                } catch (error: Exception) {
                    val message = error.message.orEmpty()
                    when {
                        Htunmobile.isTransportUnavailable(message) -> unavailable = error
                        Htunmobile.isRetryable(message) -> throw IOException(message, error)
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
        if (!nativeSession.compareAndSet(null, activeSession)) {
            nativeDialer.compareAndSet(dialer, null)
            dialer.close()
            activeSession.close()
            throw IOException("Another native tunnel is active")
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
        }, "htun-http3-upload")

        try {
            configureVpn(
                activeSession.address(),
                activeSession.dns(),
                activeSession.mtu().toString(),
                runGeneration,
            )
            val tunnelOutput = output ?: throw IOException("VPN output is unavailable")
            onConnected()
            logEvent("Connected using HTTP/3 MASQUE")
            sendStatus("Connected over HTTP/3 MASQUE")
            updateNotification("Connected over HTTP/3 MASQUE")
            sender.start()
            while (isRunActive(runGeneration) && attemptActive.get()) {
                val packet = activeSession.receive()
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
            sender.interrupt()
            if (sender.isAlive && sender !== Thread.currentThread()) {
                try {
                    sender.join(REQUEST_WRITER_STOP_TIMEOUT_MILLIS)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
            }
            nativeDialer.compareAndSet(dialer, null)
            dialer.close()
            nativeSession.compareAndSet(activeSession, null)
            try {
                activeSession.close()
            } catch (_: Exception) {
            }
        }
    }

    private fun connectLegacyOnce(
        client: OkHttpClient,
        server: String,
        token: String,
        clientId: String,
        attemptActive: AtomicBoolean,
        vpnReady: CountDownLatch,
        runGeneration: Long,
        onConnected: () -> Unit,
    ) {
        val attemptCall = AtomicReference<Call?>()
        val requestBody = TunRequestBody(attemptActive, vpnReady, attemptCall, runGeneration)
        val request = Request.Builder()
            .url(server.trimEnd('/') + "/v1/tunnel")
            .header("Authorization", "Bearer $token")
            .header("X-HTun-Version", PacketFraming.VERSION)
            .header("X-HTun-Client-ID", clientId)
            .post(requestBody)
            .build()
        val activeCall = client.newCall(request)
        attemptCall.set(activeCall)
        call = activeCall
        try {
            activeCall.execute().use { response ->
                if (!response.isSuccessful) {
                    val message = "Gateway returned HTTP ${response.code}"
                    if (response.code in 400..499 && response.code !in RETRYABLE_HTTP_CODES) {
                        throw PermanentTunnelException(message)
                    }
                    throw IOException(message)
                }
                if (response.protocol != Protocol.HTTP_2) {
                    throw PermanentTunnelException("Gateway did not negotiate HTTP/2")
                }
                configureVpn(
                    response.header("X-HTun-Address"),
                    response.header("X-HTun-DNS"),
                    response.header("X-HTun-MTU"),
                    runGeneration,
                )
                val tunnelOutput = output ?: throw IOException("VPN output is unavailable")
                vpnReady.countDown()
                onConnected()
                val responseBody = response.body ?: throw IOException("Gateway returned no response stream")
                logEvent("Connected using encrypted HTTP/2 fallback")
                sendStatus("Connected over HTTP/2")
                updateNotification("Connected over HTTP/2")
                val source = responseBody.source()
                while (isRunActive(runGeneration) && attemptActive.get()) {
                    val packet = PacketFraming.read(source) ?: continue
                    tunnelOutput.write(packet)
                    if (isRunActive(runGeneration)) {
                        downloadedBytes.addAndGet(packet.size.toLong())
                    }
                }
                if (isRunActive(runGeneration)) throw IOException("Gateway closed the tunnel")
            }
        } finally {
            requestBody.stop()
            activeCall.cancel()
            if (call === activeCall) call = null
        }
    }

    @Synchronized
    private fun configureVpn(
        addressHeader: String?,
        dnsHeader: String?,
        mtuHeader: String?,
        runGeneration: Long,
    ) {
        if (!isRunActive(runGeneration)) throw InterruptedException("Tunnel generation was replaced")
        val addressParts = addressHeader?.split('/')
        if (addressParts?.size != 2) throw PermanentTunnelException("Gateway returned an invalid lease")
        val prefix = addressParts[1].toIntOrNull()
            ?: throw PermanentTunnelException("Gateway returned an invalid lease prefix")
        val mtu = mtuHeader?.toIntOrNull() ?: 1100
        if (prefix !in 0..32 || mtu !in 576..9000) {
            throw PermanentTunnelException("Gateway returned invalid network parameters")
        }
        val configuration = VpnConfiguration(addressParts[0], prefix, dnsHeader.orEmpty(), mtu)
        if (descriptor.get() != null && vpnConfiguration == configuration) return
        closeVpn()

        val builder = Builder()
            .setSession(currentProfileName ?: "hTun")
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
                    if (count <= 0) continue
                    if (descriptor.get() !== readerDescriptor) break
                    if (!isAssignedIPv4Packet(buffer, count, sourceAddress)) continue
                    val packet = buffer.copyOf(count)
                    if (!outboundPackets.offer(packet)) {
                        outboundPackets.poll()
                        outboundPackets.offer(packet)
                    }
                }
            } catch (_: Exception) {
                if (running.get() && descriptor.get() != null) {
                    Log.w(TAG, "VPN packet reader stopped")
                }
            }
        }, "htun-vpn-reader").also { it.start() }
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
        logEvent("$reason; retrying in ${seconds}s")
        sendStatus("$reason; retrying in ${seconds}s")
        updateNotification("Reconnecting in ${seconds}s")
        return try {
            Thread.sleep(delayMillis)
            isRunActive(runGeneration)
        } catch (_: InterruptedException) {
            isRunActive(runGeneration)
        }
    }

    private fun isRunActive(runGeneration: Long): Boolean =
        running.get() && generation.get() == runGeneration

    private inner class TunRequestBody(
        private val active: AtomicBoolean,
        private val ready: CountDownLatch,
        private val ownerCall: AtomicReference<Call?>,
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
                    while (running.get() && active.get()) {
                        val packet = outboundPackets.poll(1, TimeUnit.SECONDS) ?: continue
                        if (!isRunActive(runGeneration) || !active.get()) break
                        PacketFraming.write(sink, packet)
                        if (isRunActive(runGeneration)) {
                            uploadedBytes.addAndGet(packet.size.toLong())
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
            }, "htun-http2-upload")
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
        if (!running.getAndSet(false) && descriptor.get() == null && call == null) return
        generation.incrementAndGet()
        call?.cancel()
        call = null
        closeNativeDialer()
        closeNativeSession()
        worker?.interrupt()
        stopStatsWorker()
        closeVpn()
        currentProfileId = null
        currentProfileName = null
        currentSessionId = NO_SESSION
        currentSnapshot = TrafficSnapshot(
            totalDownloadedBytes = downloadedBytes.get(),
            totalUploadedBytes = uploadedBytes.get(),
        )
        logEvent(message)
        sendStatus(message)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    @Synchronized
    private fun finishTunnel(runGeneration: Long, startId: Int, message: String) {
        if (generation.get() != runGeneration) return
        running.set(false)
        call = null
        closeNativeDialer()
        closeNativeSession()
        stopStatsWorker()
        closeVpn()
        worker = null
        currentProfileId = null
        currentProfileName = null
        currentSessionId = NO_SESSION
        currentSnapshot = TrafficSnapshot(
            totalDownloadedBytes = downloadedBytes.get(),
            totalUploadedBytes = uploadedBytes.get(),
        )
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
        selectedNetwork.set(null)
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

    private fun validConfiguration(server: String, token: String, clientId: String): Boolean = try {
        val uri = URI(server)
        uri.scheme == "https" &&
            !uri.host.isNullOrBlank() &&
            uri.userInfo == null &&
            (uri.path.isNullOrEmpty() || uri.path == "/") &&
            uri.query == null &&
            uri.fragment == null &&
            token.isNotBlank() &&
            CLIENT_ID.matches(clientId)
    } catch (_: Exception) {
        false
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
        }, "htun-traffic-stats").also { it.start() }
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
        error.message.orEmpty()
            .replace(token, "[redacted]")
            .replace(Regex("\\s+"), " ")
            .trim()
            .take(180)
            .ifBlank { error.javaClass.simpleName }

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
            .setContentTitle(currentProfileName ?: "hTun")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setOngoing(true)
            .setContentIntent(openApp)
            .addAction(
                Notification.Action.Builder(
                    Icon.createWithResource(this, R.drawable.ic_htun),
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
        const val ACTION_START = "dev.htun.android.START"
        const val ACTION_STOP = "dev.htun.android.STOP"
        const val ACTION_STATUS = "dev.htun.android.STATUS"
        const val ACTION_STATS = "dev.htun.android.STATS"
        const val EXTRA_SERVER = "server"
        const val EXTRA_TOKEN = "token"
        const val EXTRA_CLIENT_ID = "client_id"
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
        private const val CHANNEL_ID = "htun-vpn"
        private const val NOTIFICATION_ID = 1201
        private const val TAG = "hTun"
        private const val STABLE_CONNECTION_MILLIS = 30_000L
        private const val VPN_READER_STOP_TIMEOUT_MILLIS = 2_000L
        private const val REQUEST_WRITER_STOP_TIMEOUT_MILLIS = 2_000L
        private const val STATS_INTERVAL_MILLIS = 1_000L
        private const val STATS_STOP_TIMEOUT_MILLIS = 2_000L
        private const val NANOS_PER_SECOND = 1_000_000_000L
        private const val NO_SESSION = 0L
        private const val STATUS_PERMISSION = "dev.htun.android.permission.STATUS"
        private val RETRYABLE_HTTP_CODES = setOf(408, 425, 429)
        private val CLIENT_ID = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

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
        val octet = parts[index].toIntOrNull() ?: return null
        if (octet !in 0..255) return null
        result[index] = octet.toByte()
    }
    return result
}

internal fun isAssignedIPv4Packet(packet: ByteArray, length: Int, sourceAddress: ByteArray): Boolean {
    if (length < 20 || sourceAddress.size != 4 || (packet[0].toInt() ushr 4) != 4) return false
    for (index in sourceAddress.indices) {
        if (packet[12 + index] != sourceAddress[index]) return false
    }
    return true
}
