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
    private val descriptor = AtomicReference<ParcelFileDescriptor?>()
    private val selectedNetwork = AtomicReference<Network?>()
    private val outboundPackets = ArrayBlockingQueue<ByteArray>(256)
    @Volatile private var call: Call? = null
    private var input: FileInputStream? = null
    private var output: FileOutputStream? = null
    private var worker: Thread? = null
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
        if (!validConfiguration(server, token, clientId)) {
            stopTunnel("Invalid tunnel configuration")
            return START_NOT_STICKY
        }

        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification("Connecting"), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification("Connecting"))
        }
        sendStatus("Connecting")
        worker = Thread(
            { runTunnel(server, token, clientId, runGeneration, startId) },
            "htun-http2",
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
                    connectOnce(client, server, token, clientId, attemptActive, vpnReady, runGeneration) {
                        attemptConnectedAt = System.currentTimeMillis()
                    }
                } catch (error: PermanentTunnelException) {
                    finalStatus = error.message ?: "Connection rejected"
                    Log.w(TAG, "Tunnel rejected: ${error.message}")
                    break
                } catch (error: Exception) {
                    if (!isRunActive(runGeneration)) break
                    Log.w(TAG, "Tunnel interrupted: ${error.javaClass.simpleName}")
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

    private fun connectOnce(
        client: OkHttpClient,
        server: String,
        token: String,
        clientId: String,
        attemptActive: AtomicBoolean,
        vpnReady: CountDownLatch,
        runGeneration: Long,
        onConnected: () -> Unit,
    ) {
        val request = Request.Builder()
            .url(server.trimEnd('/') + "/v1/tunnel")
            .header("Authorization", "Bearer $token")
            .header("X-HTun-Version", PacketFraming.VERSION)
            .header("X-HTun-Client-ID", clientId)
            .post(TunRequestBody(attemptActive, vpnReady))
            .build()
        val activeCall = client.newCall(request)
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
                vpnReady.countDown()
                onConnected()
                val responseBody = response.body ?: throw IOException("Gateway returned no response stream")
                sendStatus("Connected over HTTP/2")
                updateNotification("Connected over HTTP/2")
                val source = responseBody.source()
                while (isRunActive(runGeneration) && attemptActive.get()) {
                    val packet = PacketFraming.read(source) ?: continue
                    output?.write(packet)
                }
                if (isRunActive(runGeneration)) throw IOException("Gateway closed the tunnel")
            }
        } finally {
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
        val mtu = mtuHeader?.toIntOrNull() ?: 1300
        if (prefix !in 0..32 || mtu !in 576..9000) {
            throw PermanentTunnelException("Gateway returned invalid network parameters")
        }
        val configuration = VpnConfiguration(addressParts[0], prefix, dnsHeader.orEmpty(), mtu)
        if (descriptor.get() != null && vpnConfiguration == configuration) return
        closeVpn()

        val builder = Builder()
            .setSession("hTun")
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
        startVpnReader()
    }

    private fun startVpnReader() {
        val readerDescriptor = descriptor.get() ?: return
        val readerInput = input ?: return
        vpnReader = Thread({
            val buffer = ByteArray(65_535)
            try {
                while (running.get() && descriptor.get() === readerDescriptor) {
                    val count = readerInput.read(buffer)
                    if (count <= 0) continue
                    if (descriptor.get() !== readerDescriptor) break
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
    ) : RequestBody() {
        override fun contentType() = PacketFraming.CONTENT_TYPE.toMediaType()
        override fun isDuplex() = true

        override fun writeTo(sink: BufferedSink) {
            PacketFraming.write(sink, byteArrayOf())
            ready.await()
            while (running.get() && active.get()) {
                val packet = outboundPackets.poll(1, TimeUnit.SECONDS) ?: continue
                PacketFraming.write(sink, packet)
            }
        }
    }

    @Synchronized
    private fun stopTunnel(message: String) {
        if (!running.getAndSet(false) && descriptor.get() == null && call == null) return
        generation.incrementAndGet()
        call?.cancel()
        call = null
        worker?.interrupt()
        closeVpn()
        sendStatus(message)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    @Synchronized
    private fun finishTunnel(runGeneration: Long, startId: Int, message: String) {
        if (generation.get() != runGeneration) return
        running.set(false)
        call = null
        closeVpn()
        worker = null
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
            Intent(ACTION_STATUS).setPackage(packageName).putExtra(EXTRA_STATUS, value),
            STATUS_PERMISSION,
        )
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
            .setContentTitle("hTun")
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
        const val EXTRA_SERVER = "server"
        const val EXTRA_TOKEN = "token"
        const val EXTRA_CLIENT_ID = "client_id"
        const val EXTRA_STATUS = "status"
        @Volatile private var currentStatus = "Disconnected"
        private const val CHANNEL_ID = "htun-vpn"
        private const val NOTIFICATION_ID = 1201
        private const val TAG = "hTun"
        private const val STABLE_CONNECTION_MILLIS = 30_000L
        private const val VPN_READER_STOP_TIMEOUT_MILLIS = 2_000L
        private const val STATUS_PERMISSION = "dev.htun.android.permission.STATUS"
        private val RETRYABLE_HTTP_CODES = setOf(408, 425, 429)
        private val CLIENT_ID = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

        fun currentStatus(): String = currentStatus
    }

    private data class VpnConfiguration(
        val address: String,
        val prefix: Int,
        val dns: String,
        val mtu: Int,
    )

    private class PermanentTunnelException(message: String) : Exception(message)
}
