package dev.htun.android

import android.Manifest
import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.Window
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
    private lateinit var statusDetail: TextView
    private lateinit var statusDot: View
    private lateinit var connectButton: Button
    private lateinit var settingsCard: LinearLayout
    private lateinit var settingsToggle: TextView
    private var pendingStart = false

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            renderStatus(intent?.getStringExtra(TunnelService.EXTRA_STATUS) ?: getString(R.string.unknown_state))
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        configureWindow()
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
        rememberToken = option(R.string.remember_token).apply {
            isChecked = stored != null
        }
        autoConnect = option(R.string.auto_connect).apply {
            isChecked = stored != null && preferences.getBoolean("auto_connect", false)
            isEnabled = rememberToken.isChecked
            alpha = if (isEnabled) 1f else 0.45f
        }
        rememberToken.setOnCheckedChangeListener { _, checked ->
            autoConnect.isEnabled = checked
            autoConnect.alpha = if (checked) 1f else 0.45f
            if (!checked) {
                autoConnect.isChecked = false
                SecureTokenStore(this).clear()
                preferences.edit().putBoolean("auto_connect", false).apply()
            }
        }
        autoConnect.setOnCheckedChangeListener { _, checked ->
            preferences.edit().putBoolean("auto_connect", checked && rememberToken.isChecked).apply()
        }

        setContentView(buildContent())
        renderStatus(TunnelService.currentStatus())

        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_NOTIFICATIONS)
        }
    }

    override fun onStart() {
        super.onStart()
        renderStatus(TunnelService.currentStatus())
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

    private fun buildContent(): View {
        val page = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(22), dp(28), dp(22), dp(36))
        }
        page.addView(TextView(this).apply {
            text = getString(R.string.app_name)
            textSize = 30f
            setTextColor(COLOR_TEXT)
            setTypeface(typeface, Typeface.BOLD)
        })
        page.addView(TextView(this).apply {
            setText(R.string.tagline)
            textSize = 14f
            setTextColor(COLOR_MUTED)
            setPadding(0, dp(3), 0, dp(24))
        })
        page.addView(connectionCard())

        settingsToggle = TextView(this).apply {
            setText(R.string.connection_settings)
            textSize = 15f
            setTextColor(COLOR_TEXT)
            gravity = Gravity.CENTER_VERTICAL
            setTypeface(typeface, Typeface.BOLD)
            setPadding(dp(18), dp(18), dp(18), dp(18))
            background = rounded(COLOR_CARD, 18f)
            setCompoundDrawablesWithIntrinsicBounds(0, 0, android.R.drawable.arrow_down_float, 0)
            setOnClickListener { toggleSettings() }
            layoutParams = marginParams(top = 14)
        }
        page.addView(settingsToggle)

        settingsCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(18), dp(18), dp(18))
            background = rounded(COLOR_CARD, 18f)
            visibility = View.GONE
            layoutParams = marginParams(top = 8)
            addView(label(R.string.gateway_label))
            addView(server)
            addView(label(R.string.token_label, 14))
            addView(token)
            addView(rememberToken)
            addView(autoConnect)
            addView(label(R.string.device_id_label, 12))
            addView(clientId)
            addView(TextView(this@MainActivity).apply {
                setText(R.string.settings_help)
                textSize = 12f
                setTextColor(COLOR_MUTED)
                setPadding(0, dp(14), 0, 0)
            })
        }
        page.addView(settingsCard)

        page.addView(TextView(this).apply {
            setText(R.string.security_note)
            textSize = 12f
            gravity = Gravity.CENTER
            setTextColor(COLOR_MUTED)
            setPadding(dp(12), dp(24), dp(12), 0)
        })

        return ScrollView(this).apply {
            setBackgroundColor(COLOR_BACKGROUND)
            isFillViewport = true
            addView(page)
        }
    }

    private fun connectionCard(): View {
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(dp(22), dp(24), dp(22), dp(22))
            background = rounded(COLOR_CARD, 24f)
        }
        val stateRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
        }
        statusDot = View(this).apply {
            background = circle(COLOR_OFFLINE)
            layoutParams = LinearLayout.LayoutParams(dp(10), dp(10)).apply {
                marginEnd = dp(9)
            }
        }
        status = TextView(this).apply {
            textSize = 20f
            setTextColor(COLOR_TEXT)
            setTypeface(typeface, Typeface.BOLD)
        }
        stateRow.addView(statusDot)
        stateRow.addView(status)
        card.addView(stateRow)

        statusDetail = TextView(this).apply {
            textSize = 13f
            gravity = Gravity.CENTER
            setTextColor(COLOR_MUTED)
            setPadding(0, dp(8), 0, dp(22))
        }
        card.addView(statusDetail)

        connectButton = Button(this).apply {
            isAllCaps = false
            textSize = 16f
            setTextColor(COLOR_BUTTON_TEXT)
            setTypeface(typeface, Typeface.BOLD)
            minHeight = dp(56)
            background = rounded(COLOR_ACCENT, 18f)
            setOnClickListener { handlePrimaryAction() }
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(56))
        }
        card.addView(connectButton)
        return card
    }

    private fun toggleSettings() {
        val opening = settingsCard.visibility != View.VISIBLE
        settingsCard.visibility = if (opening) View.VISIBLE else View.GONE
        settingsToggle.setCompoundDrawablesWithIntrinsicBounds(
            0,
            0,
            if (opening) android.R.drawable.arrow_up_float else android.R.drawable.arrow_down_float,
            0,
        )
    }

    private fun handlePrimaryAction() {
        val active = isActiveStatus(TunnelService.currentStatus())
        if (active) {
            startService(Intent(this, TunnelService::class.java).setAction(TunnelService.ACTION_STOP))
        } else {
            requestConnect()
        }
    }

    private fun renderStatus(value: String) {
        if (!::status.isInitialized) return
        val connected = value.startsWith("Connected")
        val waiting = value.startsWith("Waiting")
        val active = connected || value.startsWith("Connecting") || value.startsWith("Reconnecting") ||
            value.startsWith("Connection lost") || waiting
        status.text = when {
            connected -> getString(R.string.connected)
            waiting -> getString(R.string.waiting_for_network)
            active -> getString(R.string.connecting)
            else -> value
        }
        statusDetail.text = when {
            value.contains("HTTP/3") -> getString(R.string.transport_http3)
            value.contains("HTTP/2") -> getString(R.string.transport_http2)
            value.startsWith("Reconnecting") || value.startsWith("Connection lost") || waiting -> value
            active -> getString(R.string.establishing_secure_tunnel)
            else -> getString(R.string.ready_to_connect)
        }
        statusDot.background = circle(if (connected) COLOR_CONNECTED else if (active) COLOR_CONNECTING else COLOR_OFFLINE)
        connectButton.text = getString(if (active) R.string.disconnect else R.string.connect)
        connectButton.setTextColor(if (active) COLOR_TEXT else COLOR_BUTTON_TEXT)
        connectButton.background = rounded(if (active) COLOR_BUTTON_SECONDARY else COLOR_ACCENT, 18f)
    }

    private fun requestConnect() {
        if (!server.text.toString().startsWith("https://")) {
            showConfigurationError(R.string.https_required)
            return
        }
        if (token.text.isBlank() || !CLIENT_ID.matches(clientId.text.toString())) {
            showConfigurationError(R.string.credentials_required)
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

    private fun showConfigurationError(message: Int) {
        if (settingsCard.visibility != View.VISIBLE) toggleSettings()
        status.text = getString(message)
        statusDetail.setText(R.string.check_connection_settings)
        statusDot.background = circle(COLOR_ERROR)
    }

    private fun startTunnel() {
        val normalizedServer = server.text.toString().trimEnd('/')
        val normalizedClientId = clientId.text.toString()
        val tokenValue = token.text.toString()
        if (rememberToken.isChecked &&
            !SecureTokenStore(this).save(normalizedServer, normalizedClientId, tokenValue)
        ) {
            showConfigurationError(R.string.secure_storage_failed)
            return
        }
        if (!rememberToken.isChecked) SecureTokenStore(this).clear()
        getSharedPreferences("settings", MODE_PRIVATE).edit()
            .putString("server", normalizedServer)
            .putString("client_id", normalizedClientId)
            .putBoolean("auto_connect", autoConnect.isChecked)
            .apply()
        startForegroundService(
            Intent(this, TunnelService::class.java)
                .setAction(TunnelService.ACTION_START)
                .putExtra(TunnelService.EXTRA_SERVER, normalizedServer)
                .putExtra(TunnelService.EXTRA_TOKEN, tokenValue)
                .putExtra(TunnelService.EXTRA_CLIENT_ID, normalizedClientId),
        )
        token.text.clear()
        renderStatus("Connecting")
    }

    private fun field(hintText: String, initial: String) = EditText(this).apply {
        hint = hintText
        setText(initial)
        textSize = 15f
        setTextColor(COLOR_TEXT)
        setHintTextColor(COLOR_MUTED)
        background = rounded(COLOR_FIELD, 14f, COLOR_BORDER)
        setPadding(dp(14), 0, dp(14), 0)
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
        isSingleLine = true
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(52))
    }

    private fun option(textResource: Int) = CheckBox(this).apply {
        setText(textResource)
        textSize = 14f
        setTextColor(COLOR_TEXT)
        buttonTintList = android.content.res.ColorStateList.valueOf(COLOR_ACCENT)
        setPadding(0, dp(8), 0, 0)
    }

    private fun label(textResource: Int, topMargin: Int = 0) = TextView(this).apply {
        setText(textResource)
        textSize = 12f
        setTextColor(COLOR_MUTED)
        setTypeface(typeface, Typeface.BOLD)
        setPadding(dp(2), dp(topMargin), 0, dp(7))
    }

    private fun marginParams(top: Int) = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT,
    ).apply {
        topMargin = dp(top)
    }

    private fun rounded(fill: Int, radius: Float, stroke: Int? = null) = GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = dp(radius.toInt()).toFloat()
        setColor(fill)
        if (stroke != null) setStroke(dp(1), stroke)
    }

    private fun circle(fill: Int) = GradientDrawable().apply {
        shape = GradientDrawable.OVAL
        setColor(fill)
    }

    private fun configureWindow() {
        requestWindowFeature(Window.FEATURE_NO_TITLE)
        window.statusBarColor = COLOR_BACKGROUND
        window.navigationBarColor = COLOR_BACKGROUND
        if (Build.VERSION.SDK_INT >= 29) window.isNavigationBarContrastEnforced = false
    }

    private fun isActiveStatus(value: String): Boolean =
        value.startsWith("Connected") || value.startsWith("Connecting") ||
            value.startsWith("Reconnecting") || value.startsWith("Connection lost") ||
            value.startsWith("Waiting")

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private fun String.safeClientId(): String = replace(Regex("[^A-Za-z0-9._-]+"), "-")
        .trim('-', '.', '_').take(64).ifBlank { "android" }

    companion object {
        private const val REQUEST_VPN = 100
        private const val REQUEST_NOTIFICATIONS = 101
        private const val STATUS_PERMISSION = "dev.htun.android.permission.STATUS"
        private const val DEFAULT_SERVER = "https://htun.i-csu.org:8443"
        private val CLIENT_ID = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

        private val COLOR_BACKGROUND = Color.rgb(8, 17, 31)
        private val COLOR_CARD = Color.rgb(17, 29, 48)
        private val COLOR_FIELD = Color.rgb(11, 23, 40)
        private val COLOR_BORDER = Color.rgb(43, 61, 82)
        private val COLOR_TEXT = Color.rgb(242, 247, 252)
        private val COLOR_MUTED = Color.rgb(148, 163, 184)
        private val COLOR_ACCENT = Color.rgb(110, 231, 183)
        private val COLOR_BUTTON_TEXT = Color.rgb(5, 35, 29)
        private val COLOR_BUTTON_SECONDARY = Color.rgb(52, 72, 94)
        private val COLOR_CONNECTED = Color.rgb(74, 222, 128)
        private val COLOR_CONNECTING = Color.rgb(250, 204, 21)
        private val COLOR_OFFLINE = Color.rgb(100, 116, 139)
        private val COLOR_ERROR = Color.rgb(248, 113, 113)
    }
}

internal fun preferredGateway(server: String): String =
    if (server == "https://htun.i-csu.org") "https://htun.i-csu.org:8443" else server
