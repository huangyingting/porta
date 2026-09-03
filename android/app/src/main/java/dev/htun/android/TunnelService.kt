package dev.htun.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import okhttp3.Call
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody
import okio.BufferedSink
import okio.buffer
import okio.source
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.URI
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

class TunnelService : VpnService() {
    private val running = AtomicBoolean(false)
    private val descriptor = AtomicReference<ParcelFileDescriptor?>()
    private var ready = CountDownLatch(1)
    private var call: Call? = null
    private var input: FileInputStream? = null
    private var output: FileOutputStream? = null
    private var worker: Thread? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopTunnel("Disconnected")
            return START_NOT_STICKY
        }
        if (intent?.action != ACTION_START || running.getAndSet(true)) return START_NOT_STICKY
        ready = CountDownLatch(1)

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
        worker = Thread({ runTunnel(server, token, clientId) }, "htun-http2").also { it.start() }
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

    private fun runTunnel(server: String, token: String, clientId: String) {
        try {
            val client = OkHttpClient.Builder()
                .socketFactory(ProtectedSocketFactory(this))
                .protocols(listOf(Protocol.HTTP_2, Protocol.HTTP_1_1))
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(0, TimeUnit.MILLISECONDS)
                .writeTimeout(0, TimeUnit.MILLISECONDS)
                .pingInterval(20, TimeUnit.SECONDS)
                .build()
            val body = TunRequestBody()
            val request = Request.Builder()
                .url(server.trimEnd('/') + "/v1/tunnel")
                .header("Authorization", "Bearer $token")
                .header("X-HTun-Version", PacketFraming.VERSION)
                .header("X-HTun-Client-ID", clientId)
                .post(body)
                .build()
            val activeCall = client.newCall(request)
            call = activeCall
            activeCall.execute().use { response ->
                if (!response.isSuccessful) {
                    throw IllegalStateException("Gateway returned HTTP ${response.code}")
                }
                if (response.protocol != Protocol.HTTP_2) {
                    throw IllegalStateException("Gateway did not negotiate HTTP/2")
                }
                establishVpn(response.header("X-HTun-Address"), response.header("X-HTun-DNS"), response.header("X-HTun-MTU"))
                val responseBody = response.body ?: throw IllegalStateException("Gateway returned no response stream")
                sendStatus("Connected over HTTP/2")
                updateNotification("Connected over HTTP/2")
                val source = responseBody.source()
                while (running.get()) {
                    val packet = PacketFraming.read(source) ?: continue
                    output?.write(packet)
                }
            }
        } catch (error: Exception) {
            if (running.get()) {
                Log.w(TAG, "Tunnel stopped: ${error.javaClass.simpleName}")
                sendStatus("Connection stopped: ${error.message ?: error.javaClass.simpleName}")
            }
        } finally {
            stopTunnel("Disconnected")
        }
    }

    private fun establishVpn(addressHeader: String?, dnsHeader: String?, mtuHeader: String?) {
        val addressParts = addressHeader?.split('/')
        require(addressParts?.size == 2) { "Gateway returned an invalid lease" }
        val prefix = addressParts[1].toInt()
        val mtu = mtuHeader?.toIntOrNull() ?: 1300
        require(prefix in 0..32 && mtu in 576..9000) { "Gateway returned invalid network parameters" }

        val builder = Builder()
            .setSession("hTun")
            .setMtu(mtu)
            .addAddress(addressParts[0], prefix)
            .addRoute("0.0.0.0", 0)
            .setBlocking(true)
        if (!dnsHeader.isNullOrBlank()) builder.addDnsServer(dnsHeader)
        val vpn = builder.establish() ?: throw IllegalStateException("Android refused to establish the VPN")
        descriptor.set(vpn)
        input = FileInputStream(vpn.fileDescriptor)
        output = FileOutputStream(vpn.fileDescriptor)
        ready.countDown()
    }

    private inner class TunRequestBody : RequestBody() {
        override fun contentType() = PacketFraming.CONTENT_TYPE.toMediaType()
        override fun isDuplex() = true

        override fun writeTo(sink: BufferedSink) {
            ready.await()
            val buffer = ByteArray(65_535)
            while (running.get()) {
                val count = input?.read(buffer) ?: break
                if (count <= 0) continue
                PacketFraming.write(sink, buffer.copyOf(count))
            }
        }
    }

    @Synchronized
    private fun stopTunnel(message: String) {
        if (!running.getAndSet(false) && descriptor.get() == null && call == null) return
        ready.countDown()
        call?.cancel()
        call = null
        try { descriptor.getAndSet(null)?.close() } catch (_: Exception) {}
        input = null
        output = null
        sendStatus(message)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
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
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("hTun")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setOngoing(true)
            .setContentIntent(openApp)
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
        private const val CHANNEL_ID = "htun-vpn"
        private const val NOTIFICATION_ID = 1201
        private const val TAG = "hTun"
        private const val STATUS_PERMISSION = "dev.htun.android.permission.STATUS"
        private val CLIENT_ID = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    }
}
