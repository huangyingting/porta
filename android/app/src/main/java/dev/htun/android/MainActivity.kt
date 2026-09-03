package dev.htun.android

import android.Manifest
import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

class MainActivity : Activity() {
    private lateinit var server: EditText
    private lateinit var token: EditText
    private lateinit var clientId: EditText
    private lateinit var rememberToken: CheckBox
    private lateinit var autoConnect: CheckBox
    private lateinit var status: TextView
    private var pendingStart = false

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            status.text = intent?.getStringExtra(TunnelService.EXTRA_STATUS) ?: "Unknown state"
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val preferences = getSharedPreferences("settings", MODE_PRIVATE)
        val stored = SecureTokenStore(this).load()

        server = field(
            getString(R.string.gateway_hint),
            preferredGateway(
                stored?.server ?: preferences.getString("server", DEFAULT_SERVER) ?: DEFAULT_SERVER,
            ),
        )
        clientId = field(
            getString(R.string.client_id_hint),
            stored?.clientId ?: preferences.getString("client_id", Build.MODEL.safeClientId()) ?: "android",
        )
        token = field(getString(R.string.token_hint), stored?.token ?: "").apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        rememberToken = CheckBox(this).apply {
            setText(R.string.remember_token)
            isChecked = stored != null
        }
        autoConnect = CheckBox(this).apply {
            setText(R.string.auto_connect)
            isChecked = stored != null && preferences.getBoolean("auto_connect", false)
            isEnabled = rememberToken.isChecked
        }
        rememberToken.setOnCheckedChangeListener { _, checked ->
            autoConnect.isEnabled = checked
            if (!checked) {
                autoConnect.isChecked = false
                SecureTokenStore(this).clear()
                preferences.edit().putBoolean("auto_connect", false).apply()
            }
        }
        autoConnect.setOnCheckedChangeListener { _, checked ->
            preferences.edit().putBoolean("auto_connect", checked && rememberToken.isChecked).apply()
        }
        status = TextView(this).apply {
            setText(R.string.disconnected)
            setPadding(0, 24, 0, 24)
        }

        val connect = Button(this).apply {
            setText(R.string.connect_http2)
            setOnClickListener { requestConnect() }
        }
        val disconnect = Button(this).apply {
            setText(R.string.disconnect)
            setOnClickListener {
                startService(Intent(this@MainActivity, TunnelService::class.java).setAction(TunnelService.ACTION_STOP))
            }
        }

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(40, 48, 40, 48)
            addView(TextView(this@MainActivity).apply {
                setText(R.string.app_name)
                textSize = 30f
            })
            addView(TextView(this@MainActivity).apply {
                setText(R.string.description)
                setPadding(0, 8, 0, 24)
            })
            addView(server)
            addView(token)
            addView(rememberToken)
            addView(autoConnect)
            addView(clientId)
            addView(connect)
            addView(disconnect)
            addView(status)
        }
        setContentView(ScrollView(this).apply { addView(content) })

        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_NOTIFICATIONS)
        }
    }

    override fun onStart() {
        super.onStart()
        status.text = TunnelService.currentStatus()
        registerReceiver(
            statusReceiver,
            IntentFilter(TunnelService.ACTION_STATUS),
            STATUS_PERMISSION,
            null,
            Context.RECEIVER_NOT_EXPORTED,
        )
    }

    override fun onStop() {
        unregisterReceiver(statusReceiver)
        super.onStop()
    }

    @Deprecated("VpnService preparation still uses the activity-result contract")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN && resultCode == RESULT_OK && pendingStart) startTunnel()
        pendingStart = false
    }

    private fun requestConnect() {
        if (!server.text.toString().startsWith("https://")) {
            status.setText(R.string.https_required)
            return
        }
        if (token.text.isBlank() || !CLIENT_ID.matches(clientId.text.toString())) {
            status.setText(R.string.credentials_required)
            return
        }
        pendingStart = true
        val prepare = VpnService.prepare(this)
        if (prepare == null) {
            startTunnel()
            pendingStart = false
        } else {
            @Suppress("DEPRECATION")
            startActivityForResult(prepare, REQUEST_VPN)
        }
    }

    private fun startTunnel() {
        val normalizedServer = server.text.toString().trimEnd('/')
        val normalizedClientId = clientId.text.toString()
        val tokenValue = token.text.toString()
        if (rememberToken.isChecked &&
            !SecureTokenStore(this).save(normalizedServer, normalizedClientId, tokenValue)
        ) {
            status.setText(R.string.secure_storage_failed)
            return
        }
        if (!rememberToken.isChecked) SecureTokenStore(this).clear()
        getSharedPreferences("settings", MODE_PRIVATE).edit()
            .putString("server", normalizedServer)
            .putString("client_id", normalizedClientId)
            .putBoolean("auto_connect", autoConnect.isChecked)
            .apply()
        val intent = Intent(this, TunnelService::class.java)
            .setAction(TunnelService.ACTION_START)
            .putExtra(TunnelService.EXTRA_SERVER, normalizedServer)
            .putExtra(TunnelService.EXTRA_TOKEN, tokenValue)
            .putExtra(TunnelService.EXTRA_CLIENT_ID, normalizedClientId)
        startForegroundService(intent)
        token.text.clear()
    }

    private fun field(hintText: String, initial: String) = EditText(this).apply {
        hint = hintText
        setText(initial)
        layoutParams = ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        setPadding(0, 14, 0, 14)
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
        isSingleLine = true
    }

    private fun String.safeClientId(): String = replace(Regex("[^A-Za-z0-9._-]+"), "-")
        .trim('-', '.', '_').take(64).ifBlank { "android" }

    companion object {
        private const val REQUEST_VPN = 100
        private const val REQUEST_NOTIFICATIONS = 101
        private const val STATUS_PERMISSION = "dev.htun.android.permission.STATUS"
        private const val DEFAULT_SERVER = "https://htun.i-csu.org:8443"
        private val CLIENT_ID = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    }
}

internal fun preferredGateway(server: String): String =
    if (server == "https://htun.i-csu.org") "https://htun.i-csu.org:8443" else server
