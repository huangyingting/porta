package dev.porta.android

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.app.AlertDialog
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
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
import android.os.PersistableBundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.view.WindowInsets
import android.view.WindowManager
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

class MainActivity : Activity() {
    private lateinit var profileStore: VpnProfileStore
    private lateinit var profilesContainer: LinearLayout
    private lateinit var status: TextView
    private lateinit var statusDetail: TextView
    private lateinit var statusDot: View
    private lateinit var bandwidthChart: BandwidthChartView
    private lateinit var downloadRate: TextView
    private lateinit var uploadRate: TextView
    private lateinit var trafficTotal: TextView
    private lateinit var trafficState: TextView
    private var pendingProfileId: String? = null
    private var clientLogDialog: AlertDialog? = null
    private var clientLogView: TextView? = null
    private var clientLogScroll: ScrollView? = null
    private var displayedLogEntries: List<ClientLogEntry>? = null
    private val refreshLog = object : Runnable {
        override fun run() {
            if (clientLogDialog?.isShowing != true) return
            refreshClientLog()
            clientLogView?.postDelayed(this, 1_000)
        }
    }

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val sessionId = intent?.getLongExtra(TunnelService.EXTRA_SESSION_ID, 0L) ?: 0L
            if (sessionId != TunnelService.currentSessionId()) return
            if (intent?.action == TunnelService.ACTION_STATS) {
                updateBandwidth(
                    TrafficSnapshot(
                        downloadBytesPerSecond = intent.getLongExtra(TunnelService.EXTRA_DOWNLOAD_BPS, 0),
                        uploadBytesPerSecond = intent.getLongExtra(TunnelService.EXTRA_UPLOAD_BPS, 0),
                        totalDownloadedBytes = intent.getLongExtra(TunnelService.EXTRA_TOTAL_DOWNLOAD, 0),
                        totalUploadedBytes = intent.getLongExtra(TunnelService.EXTRA_TOTAL_UPLOAD, 0),
                    ),
                    addSample = true,
                )
            } else {
                render(intent?.getStringExtra(TunnelService.EXTRA_STATUS) ?: getString(R.string.unknown_state))
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        configureWindow()
        profileStore = VpnProfileStore(this)
        pendingProfileId = savedInstanceState?.getString(STATE_PENDING_PROFILE)
        setContentView(buildContent())
        render(TunnelService.currentStatus())

        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_NOTIFICATIONS)
        }
    }

    @SuppressLint("UnspecifiedRegisterReceiverFlag")
    override fun onStart() {
        super.onStart()
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(
                statusReceiver,
                statusIntentFilter(),
                STATUS_PERMISSION,
                null,
                Context.RECEIVER_NOT_EXPORTED,
            )
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(
                statusReceiver,
                statusIntentFilter(),
                STATUS_PERMISSION,
                null,
            )
        }
        render(TunnelService.currentStatus())
        clientLogView?.post(refreshLog)
    }

    override fun onStop() {
        clientLogView?.removeCallbacks(refreshLog)
        unregisterReceiver(statusReceiver)
        super.onStop()
    }

    override fun onDestroy() {
        clientLogDialog?.dismiss()
        super.onDestroy()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        pendingProfileId?.let { outState.putString(STATE_PENDING_PROFILE, it) }
    }

    @Deprecated("VpnService preparation still uses the activity-result contract")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_QR) {
            if (resultCode == QrScannerActivity.RESULT_ENTER_MANUALLY) {
                showProfileDialog(null)
            } else if (resultCode == RESULT_OK) {
                importProfileSetup(data?.getStringExtra(QrScannerActivity.EXTRA_PAYLOAD), ::scanProfileQr)
            }
            return
        }
        if (requestCode == REQUEST_VPN) {
            if (resultCode == RESULT_OK) {
                val profileId = pendingProfileId
                profileStore.profiles().firstOrNull { it.id == profileId }?.let(::startProfile)
            } else {
                render(TunnelService.currentStatus())
            }
            pendingProfileId = null
        }
    }

    private fun buildContent(): View {
        val page = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        header.addView(ImageView(this).apply {
            setImageResource(R.drawable.ic_porta)
            contentDescription = null
            layoutParams = LinearLayout.LayoutParams(dp(48), dp(48)).apply {
                marginEnd = dp(12)
            }
        })
        header.addView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(TextView(this@MainActivity).apply {
                setText(R.string.app_name)
                textSize = 29f
                setTextColor(COLOR_TEXT)
                setTypeface(typeface, Typeface.BOLD)
            })
            addView(TextView(this@MainActivity).apply {
                setText(R.string.profile_tagline)
                textSize = 13f
                setTextColor(COLOR_MUTED)
                setPadding(0, dp(2), 0, 0)
            })
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        })
        header.addView(TextView(this).apply {
            setText(R.string.log)
            textSize = 14f
            setTextColor(COLOR_ACCENT)
            setTypeface(typeface, Typeface.BOLD)
            gravity = Gravity.CENTER
            setPadding(dp(12), dp(10), dp(12), dp(10))
            setOnClickListener { showClientLog() }
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                dp(48),
            ).apply {
                marginEnd = dp(8)
            }
        })
        header.addView(Button(this).apply {
            text = "+"
            contentDescription = getString(R.string.add_profile)
            textSize = 24f
            setTextColor(COLOR_BUTTON_TEXT)
            background = circle(COLOR_ACCENT)
            minWidth = 0
            minHeight = 0
            setPadding(0, 0, 0, dp(2))
            layoutParams = LinearLayout.LayoutParams(dp(48), dp(48))
            setOnClickListener { showAddProfileChooser() }
        })
        page.addView(header)
        page.addView(connectionSummary().apply {
            layoutParams = marginParams(top = 22)
        })
        page.addView(bandwidthCard().apply {
            layoutParams = marginParams(top = 12)
        })
        page.addView(TextView(this).apply {
            setText(R.string.vpn_profiles)
            textSize = 13f
            setTextColor(COLOR_MUTED)
            setTypeface(typeface, Typeface.BOLD)
            setPadding(dp(2), dp(25), 0, dp(10))
        })
        page.addView(TextView(this).apply {
            setText(R.string.profile_swipe_hint)
            textSize = 12f
            setTextColor(COLOR_MUTED)
            setPadding(dp(2), 0, dp(2), dp(12))
        })
        profilesContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        page.addView(profilesContainer)
        page.addView(TextView(this).apply {
            setText(R.string.security_note)
            textSize = 12f
            gravity = Gravity.CENTER
            setTextColor(COLOR_MUTED)
            setPadding(dp(12), dp(25), dp(12), 0)
        })

        return ScrollView(this).apply {
            setBackgroundColor(COLOR_BACKGROUND)
            isFillViewport = true
            addView(page)
            setOnApplyWindowInsetsListener { _, insets ->
                applyPageInsets(page, insets)
                insets
            }
            requestApplyInsets()
        }
    }

    @Suppress("DEPRECATION")
    private fun applyPageInsets(page: View, insets: WindowInsets) {
        val left: Int
        val top: Int
        val right: Int
        val bottom: Int
        if (Build.VERSION.SDK_INT >= 30) {
            val safeInsets = insets.getInsets(
                WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout(),
            )
            left = safeInsets.left
            top = safeInsets.top
            right = safeInsets.right
            bottom = safeInsets.bottom
        } else {
            left = insets.systemWindowInsetLeft
            top = insets.systemWindowInsetTop
            right = insets.systemWindowInsetRight
            bottom = insets.systemWindowInsetBottom
        }
        page.setPadding(
            dp(20) + left,
            dp(24) + top,
            dp(20) + right,
            dp(36) + bottom,
        )
    }

    private fun connectionSummary(): View {
        return LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(18), dp(17), dp(18), dp(17))
            background = rounded(COLOR_CARD, 18f)

            statusDot = View(this@MainActivity).apply {
                background = circle(COLOR_OFFLINE)
                layoutParams = LinearLayout.LayoutParams(dp(12), dp(12)).apply {
                    marginEnd = dp(13)
                }
            }
            addView(statusDot)
            addView(LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.VERTICAL
                status = TextView(this@MainActivity).apply {
                    textSize = 17f
                    setTextColor(COLOR_TEXT)
                    setTypeface(typeface, Typeface.BOLD)
                }
                statusDetail = TextView(this@MainActivity).apply {
                    textSize = 12f
                    setTextColor(COLOR_MUTED)
                    setPadding(0, dp(3), 0, 0)
                }
                addView(status)
                addView(statusDetail)
            })
        }
    }

    private fun bandwidthCard(): View {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(17), dp(15), dp(17), dp(14))
            background = rounded(COLOR_CARD, 18f)
            addView(LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                addView(TextView(this@MainActivity).apply {
                    setText(R.string.traffic)
                    textSize = 13f
                    setTextColor(COLOR_TEXT)
                    setTypeface(typeface, Typeface.BOLD)
                    layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                })
                trafficState = TextView(this@MainActivity).apply {
                    setText(R.string.live)
                    textSize = 10f
                    setTextColor(COLOR_ACCENT)
                    setTypeface(typeface, Typeface.BOLD)
                }
                addView(trafficState)
            })
            bandwidthChart = BandwidthChartView(this@MainActivity).apply {
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    dp(112),
                ).apply {
                    topMargin = dp(12)
                    bottomMargin = dp(12)
                }
            }
            addView(bandwidthChart)
            addView(LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                downloadRate = trafficValue(R.string.download, COLOR_ACCENT)
                uploadRate = trafficValue(R.string.upload, COLOR_UPLOAD)
                addView(downloadRate, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                addView(uploadRate, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            })
            trafficTotal = TextView(this@MainActivity).apply {
                textSize = 11f
                setTextColor(COLOR_MUTED)
                gravity = Gravity.CENTER
                setPadding(0, dp(10), 0, 0)
            }
            addView(trafficTotal)
        }
    }

    private fun trafficValue(labelResource: Int, color: Int) = TextView(this).apply {
        textSize = 12f
        setTextColor(color)
        setTypeface(typeface, Typeface.BOLD)
        gravity = Gravity.CENTER
        text = getString(labelResource, formatDataRate(0))
    }

    private fun render(value: String) {
        if (!::status.isInitialized) return
        val connected = value.startsWith("Connected")
        val blocked = value.startsWith("Connection blocked")
        val waiting = value.startsWith("Waiting")
        val active = isActiveStatus(value)
        status.text = when {
            connected -> getString(R.string.connected)
            blocked -> getString(R.string.connection_blocked)
            waiting -> getString(R.string.waiting_for_network)
            active -> getString(R.string.connecting)
            else -> getString(R.string.disconnected)
        }
        statusDetail.text = when {
            value.contains("HTTP/3") -> getString(R.string.transport_http3)
            value.contains("HTTP/2") -> getString(R.string.transport_http2)
            blocked -> value.substringAfter(": ", getString(R.string.connection_blocked))
            value.startsWith("Reconnecting") || value.startsWith("Connection lost") || waiting -> value
            active -> getString(R.string.establishing_secure_tunnel)
            else -> getString(R.string.choose_profile)
        }
        if (connected) {
            TunnelService.currentConnectionDetails()?.let { details ->
                statusDetail.append(
                    "\n" + getString(
                        if (details.automaticMtu) R.string.connection_auto_mtu else R.string.connection_mtu,
                        details.mtu,
                    ),
                )
            }
        }
        statusDot.background = circle(
            when {
                connected -> COLOR_CONNECTED
                blocked -> COLOR_DELETE
                active -> COLOR_CONNECTING
                else -> COLOR_OFFLINE
            },
        )
        trafficState.setText(if (active && !blocked) R.string.live else R.string.idle)
        trafficState.setTextColor(if (active && !blocked) COLOR_ACCENT else COLOR_MUTED)
        updateBandwidth(TunnelService.currentTrafficSnapshot(), addSample = false)
        renderProfiles()
    }

    private fun updateBandwidth(snapshot: TrafficSnapshot, addSample: Boolean) {
        if (!::bandwidthChart.isInitialized) return
        if (addSample) {
            bandwidthChart.addSample(
                snapshot.downloadBytesPerSecond,
                snapshot.uploadBytesPerSecond,
            )
        }
        downloadRate.text = getString(R.string.download, formatDataRate(snapshot.downloadBytesPerSecond))
        uploadRate.text = getString(R.string.upload, formatDataRate(snapshot.uploadBytesPerSecond))
        trafficTotal.text = getString(
            R.string.traffic_total,
            formatDataSize(snapshot.totalDownloadedBytes),
            formatDataSize(snapshot.totalUploadedBytes),
        )
    }

    private fun renderProfiles() {
        if (!::profilesContainer.isInitialized) return
        profilesContainer.removeAllViews()
        val (snapshot, result) = profileStore.read()
        val profiles = result.profiles
        if (result.needsRecovery) {
            profilesContainer.addView(profileRecovery(snapshot, result))
        } else if (profileStore.archiveCount() > 0) {
            profilesContainer.addView(profileArchives())
        }
        if (profiles.isEmpty()) {
            if (!result.needsRecovery) profilesContainer.addView(emptyProfiles())
            return
        }
        val activeProfileId = TunnelService.currentProfileId()
        profiles.forEachIndexed { index, profile ->
            profilesContainer.addView(
                profileCard(profile, activeProfileId).apply {
                    if (index > 0) layoutParams = marginParams(top = 10)
                },
            )
        }
    }

    private fun profileRecovery(snapshot: ProfileSnapshot, result: ProfileReadResult): View =
        LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(17), dp(16), dp(17), dp(16))
            background = rounded(COLOR_CARD, 18f, COLOR_DELETE_DARK)
            val message = TextView(this@MainActivity).apply {
                text = getString(R.string.profile_recovery_warning, result.profiles.size)
                setTextColor(COLOR_TEXT)
                textSize = 13f
            }
            addView(message)
            addView(Button(this@MainActivity).apply {
                setText(R.string.profile_storage_retry)
                isAllCaps = false
                setOnClickListener { renderProfiles() }
            })
            val consent = CheckBox(this@MainActivity).apply {
                setText(R.string.profile_recovery_consent)
                setTextColor(COLOR_TEXT)
            }
            addView(consent)
            addView(Button(this@MainActivity).apply {
                setText(R.string.profile_recovery_action)
                isAllCaps = false
                isEnabled = false
                consent.setOnCheckedChangeListener { _, checked -> isEnabled = checked }
                setOnClickListener {
                    if (profileStore.recover(snapshot)) {
                        renderProfiles()
                    } else {
                        message.setText(R.string.profile_recovery_failed)
                        consent.isChecked = false
                    }
                }
            })
            layoutParams = marginParams(top = 10).apply { bottomMargin = dp(10) }
        }

    private fun profileArchives(): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        val message = TextView(this@MainActivity).apply {
            setText(R.string.profile_archives_retained)
            setTextColor(COLOR_MUTED)
            textSize = 12f
        }
        addView(message)
        addView(Button(this@MainActivity).apply {
            setText(R.string.profile_archives_retry)
            isAllCaps = false
            setOnClickListener {
                val restored = profileStore.restoreArchives()
                if (restored > 0) renderProfiles()
                else message.setText(
                    if (restored == 0) R.string.profile_archives_unavailable
                    else R.string.profile_recovery_failed,
                )
            }
        })
    }

    private fun profileCard(profile: VpnProfile, activeProfileId: String?): View {
        val selected = profile.id == profileStore.selectedProfileId()
        val active = profile.id == activeProfileId && isActiveStatus(TunnelService.currentStatus())
        val anotherProfileActive = activeProfileId != null && activeProfileId != profile.id &&
            isActiveStatus(TunnelService.currentStatus())
        val controls = mutableListOf<View>()
        val nameLabel = TextView(this).apply {
            text = profile.name
            textSize = 16f
            setTextColor(COLOR_TEXT)
            setTypeface(typeface, Typeface.BOLD)
            maxLines = 1
        }
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(17), dp(16), dp(13), dp(14))
            background = rounded(COLOR_CARD, 18f, if (selected) COLOR_ACCENT_DARK else COLOR_BORDER)

            val top = LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            top.addView(TextView(this@MainActivity).apply {
                text = profile.name.firstOrNull()?.uppercase() ?: "V"
                gravity = Gravity.CENTER
                textSize = 16f
                setTextColor(COLOR_ACCENT)
                setTypeface(typeface, Typeface.BOLD)
                background = circle(COLOR_ICON)
                layoutParams = LinearLayout.LayoutParams(dp(43), dp(43)).apply {
                    marginEnd = dp(13)
                }
            })
            top.addView(LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.VERTICAL
                addView(nameLabel)
                addView(TextView(this@MainActivity).apply {
                    text = profile.server.removePrefix("https://")
                    textSize = 12f
                    setTextColor(COLOR_MUTED)
                    maxLines = 1
                })
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            })
            @Suppress("DEPRECATION")
            top.addView(Switch(this@MainActivity).apply {
                controls += this
                isChecked = active
                isEnabled = !anotherProfileActive
                thumbTintList = switchThumbColors()
                trackTintList = switchTrackColors()
                setOnCheckedChangeListener { _, checked ->
                    if (checked) requestConnect(profile) else disconnectProfile(profile)
                }
            })
            addView(top)

            addView(LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(0, dp(11), 0, 0)
                addView(TextView(this@MainActivity).apply {
                    text = when {
                        active -> profileStatus(TunnelService.currentStatus())
                        profile.autoConnect -> getString(R.string.auto_connect_enabled)
                        selected -> getString(R.string.selected_profile)
                        else -> getString(R.string.profile_ready)
                    }
                    textSize = 12f
                    setTextColor(if (active) COLOR_ACCENT else COLOR_MUTED)
                    layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                })
            })
        }
        return SwipeProfileLayout(
            this,
            card,
            controls,
            nameLabel,
            canSwipe = { !profileIsActive(profile.id) },
            onAction = { profileAction(profile, it) },
            editColor = COLOR_ACCENT_DARK,
            deleteColor = COLOR_DELETE_DARK,
            textColor = COLOR_TEXT,
        )
    }

    private fun profileAction(profile: VpnProfile, action: ProfileSwipeAction) {
        when (action) {
            ProfileSwipeAction.EDIT -> showProfileDialog(profile)
            ProfileSwipeAction.DELETE -> confirmDeleteProfile(profile)
        }
    }

    private fun profileIsActive(profileId: String): Boolean =
        profileId == TunnelService.currentProfileId() && isActiveStatus(TunnelService.currentStatus())

    private fun emptyProfiles(): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        gravity = Gravity.CENTER
        setPadding(dp(24), dp(30), dp(24), dp(30))
        background = rounded(COLOR_CARD, 18f, COLOR_BORDER)
        addView(TextView(this@MainActivity).apply {
            setText(R.string.no_profiles)
            textSize = 17f
            setTextColor(COLOR_TEXT)
            setTypeface(typeface, Typeface.BOLD)
        })
        addView(TextView(this@MainActivity).apply {
            setText(R.string.no_profiles_detail)
            textSize = 13f
            gravity = Gravity.CENTER
            setTextColor(COLOR_MUTED)
            setPadding(0, dp(7), 0, dp(17))
        })
        addView(Button(this@MainActivity).apply {
            setText(R.string.add_profile)
            isAllCaps = false
            setTextColor(COLOR_BUTTON_TEXT)
            setTypeface(typeface, Typeface.BOLD)
            background = rounded(COLOR_ACCENT, 14f)
            setOnClickListener { showAddProfileChooser() }
        })
    }

    private fun showAddProfileChooser() {
        AlertDialog.Builder(this)
            .setTitle(R.string.add_profile)
            .setItems(arrayOf(getString(R.string.scan_qr_code), getString(R.string.paste_setup), getString(R.string.enter_manually))) { _, which ->
                when (which) {
                    0 -> scanProfileQr()
                    1 -> pasteProfileSetup()
                    else -> showProfileDialog(null)
                }
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun scanProfileQr() {
        @Suppress("DEPRECATION")
        startActivityForResult(Intent(this, QrScannerActivity::class.java), REQUEST_QR)
    }

    private fun pasteProfileSetup() {
        val clipboard = getSystemService(ClipboardManager::class.java)?.primaryClip
        val text = clipboard?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text
            ?.takeIf { it.length <= 2048 }?.toString()
        importProfileSetup(text, ::pasteProfileSetup)
    }

    private fun importProfileSetup(payload: String?, retry: () -> Unit) {
        val draft = qrProfileDraft(true, payload)
        if (draft != null) {
            showProfileDialog(null, draft)
        } else {
            AlertDialog.Builder(this)
                .setMessage(R.string.qr_invalid_profile)
                .setPositiveButton(R.string.qr_retry) { _, _ -> retry() }
                .setNegativeButton(R.string.cancel, null)
                .show()
        }
    }

    private fun showProfileDialog(existing: VpnProfile?, imported: VpnProfile? = null) {
        if (existing != null && profileIsActive(existing.id)) {
            Toast.makeText(this, R.string.disconnect_before_editing, Toast.LENGTH_SHORT).show()
            return
        }
        val initial = existing ?: imported
        val name = dialogField(R.string.profile_name_hint, initial?.name.orEmpty())
        val server = dialogField(
            R.string.gateway_hint,
            initial?.server.orEmpty(),
        )
        val token = dialogField(
            if (existing == null) R.string.token_hint else R.string.token_unchanged_hint,
            imported?.token.orEmpty(),
        ).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        val autoConnect = CheckBox(this).apply {
            setText(R.string.auto_connect)
            isChecked = existing?.autoConnect ?: false
            setTextColor(COLOR_TEXT)
            buttonTintList = android.content.res.ColorStateList.valueOf(COLOR_ACCENT)
        }
        val form = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(4), dp(4), dp(4), 0)
            addView(dialogLabel(R.string.profile_name))
            addView(name)
            addView(dialogLabel(R.string.gateway_label))
            addView(server)
            addView(dialogLabel(R.string.token_label))
            addView(token)
            addView(TextView(this@MainActivity).apply {
                setText(R.string.device_identity_automatic)
                textSize = 12f
                setTextColor(COLOR_MUTED)
                setPadding(dp(2), dp(14), dp(2), dp(4))
            })
            addView(autoConnect)
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle(if (existing == null) R.string.add_profile else R.string.edit_profile)
            .setView(ScrollView(this).apply { addView(form) })
            .setPositiveButton(R.string.save, null)
            .setNegativeButton(R.string.cancel, null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                if (existing != null && profileIsActive(existing.id)) {
                    Toast.makeText(this, R.string.disconnect_before_editing, Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }
                val profile = VpnProfile(
                    id = initial?.id ?: UUID.randomUUID().toString(),
                    name = name.text.toString().trim(),
                    server = server.text.toString().trim().trimEnd('/'),
                    token = token.text.toString().ifBlank { existing?.token.orEmpty() },
                    autoConnect = autoConnect.isChecked,
                )
                val error = profileValidationError(profile)
                if (error != null) {
                    Toast.makeText(this, error, Toast.LENGTH_LONG).show()
                    return@setOnClickListener
                }
                if (!profileStore.save(profile)) {
                    Toast.makeText(this, R.string.secure_storage_failed, Toast.LENGTH_LONG).show()
                    return@setOnClickListener
                }
                if (profileStore.selectedProfileId() == null) profileStore.select(profile.id)
                dialog.dismiss()
                render(TunnelService.currentStatus())
            }
        }
        dialog.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        dialog.show()
    }

    private fun showClientLog() {
        if (clientLogDialog?.isShowing == true) return
        val logView = TextView(this).apply {
            textSize = 12f
            setTextColor(COLOR_TEXT)
            typeface = Typeface.MONOSPACE
            setPadding(dp(18), dp(12), dp(18), dp(18))
            setTextIsSelectable(true)
        }
        val scroll = ScrollView(this).apply { addView(logView) }
        val dialog = AlertDialog.Builder(this)
            .setTitle(R.string.connection_log)
            .setView(scroll)
            .setPositiveButton(R.string.copy_log, null)
            .setNegativeButton(R.string.close, null)
            .setNeutralButton(R.string.clear_log, null)
            .create()
        clientLogDialog = dialog
        clientLogView = logView
        clientLogScroll = scroll
        displayedLogEntries = null
        dialog.setOnDismissListener {
            logView.removeCallbacks(refreshLog)
            if (clientLogDialog === dialog) {
                clientLogDialog = null
                clientLogView = null
                clientLogScroll = null
                displayedLogEntries = null
            }
        }
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener { copyClientLog() }
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener {
                ClientLogStore(this).clear()
                logView.text = ""
                displayedLogEntries = null
                refreshClientLog()
            }
            logView.post(refreshLog)
        }
        dialog.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        dialog.show()
    }

    private fun refreshClientLog() {
        val view = clientLogView ?: return
        val scroll = clientLogScroll ?: return
        val entries = ClientLogStore(this).entries()
        if (entries == displayedLogEntries || view.hasSelection()) return
        val followLatest = !scroll.canScrollVertically(1)
        displayedLogEntries = entries
        val formatter = SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.getDefault())
        view.text = if (entries.isEmpty()) getString(R.string.log_empty) else entries.joinToString("\n\n") {
            "${formatter.format(Date(it.timestampMillis))}\n${it.message}"
        }
        clientLogDialog?.getButton(AlertDialog.BUTTON_POSITIVE)?.isEnabled = entries.isNotEmpty()
        if (followLatest) scroll.post { scroll.fullScroll(View.FOCUS_DOWN) }
    }

    private fun copyClientLog() {
        val view = clientLogView ?: return
        val clipboard = getSystemService(ClipboardManager::class.java)
        if (clipboard == null) {
            Toast.makeText(this, R.string.log_copy_failed, Toast.LENGTH_SHORT).show()
            return
        }
        val clip = ClipData.newPlainText(getString(R.string.connection_log), view.text)
        if (Build.VERSION.SDK_INT >= 33) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        try {
            clipboard.setPrimaryClip(clip)
            Toast.makeText(this, R.string.log_copied, Toast.LENGTH_SHORT).show()
        } catch (_: SecurityException) {
            Toast.makeText(this, R.string.log_copy_failed, Toast.LENGTH_SHORT).show()
        }
    }

    private fun confirmDeleteProfile(profile: VpnProfile) {
        if (profileIsActive(profile.id)) {
            Toast.makeText(this, R.string.disconnect_before_deleting, Toast.LENGTH_SHORT).show()
            return
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle(R.string.delete_profile)
            .setMessage(getString(R.string.delete_profile_confirmation, profile.name))
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.delete) { _, _ -> deleteProfile(profile) }
            .create()
        dialog.setOnShowListener { dialog.getButton(AlertDialog.BUTTON_NEGATIVE).requestFocus() }
        dialog.show()
    }

    private fun deleteProfile(profile: VpnProfile) {
        if (profileIsActive(profile.id)) {
            Toast.makeText(this, R.string.disconnect_before_deleting, Toast.LENGTH_SHORT).show()
            return
        }
        if (!profileStore.delete(profile.id)) {
            Toast.makeText(this, R.string.profile_delete_failed, Toast.LENGTH_LONG).show()
            return
        }
        if (profileStore.selectedProfileId() == profile.id) {
            profileStore.select(profileStore.profiles().firstOrNull()?.id)
        }
        render(TunnelService.currentStatus())
    }

    private fun requestConnect(profile: VpnProfile) {
        val activeProfileId = TunnelService.currentProfileId()
        if (activeProfileId != null && activeProfileId != profile.id &&
            isActiveStatus(TunnelService.currentStatus())
        ) {
            Toast.makeText(this, R.string.disconnect_active_profile, Toast.LENGTH_SHORT).show()
            renderProfiles()
            return
        }
        pendingProfileId = profile.id
        val prepare = VpnService.prepare(this)
        if (prepare == null) {
            startProfile(profile)
            pendingProfileId = null
        } else {
            @Suppress("DEPRECATION")
            startActivityForResult(prepare, REQUEST_VPN)
        }
    }

    private fun startProfile(profile: VpnProfile) {
        profileStore.select(profile.id)
        bandwidthChart.reset()
        updateBandwidth(TrafficSnapshot(), addSample = false)
        startForegroundService(
            Intent(this, TunnelService::class.java)
                .setAction(TunnelService.ACTION_START)
                .putExtra(TunnelService.EXTRA_PROFILE_ID, profile.id)
                .putExtra(TunnelService.EXTRA_PROFILE_NAME, profile.name)
                .putExtra(TunnelService.EXTRA_SERVER, profile.server)
                .putExtra(TunnelService.EXTRA_TOKEN, profile.token),
        )
        render("Connecting")
    }

    private fun disconnectProfile(profile: VpnProfile) {
        if (TunnelService.currentProfileId() != profile.id) {
            renderProfiles()
            return
        }
        startService(Intent(this, TunnelService::class.java).setAction(TunnelService.ACTION_STOP))
    }

    private fun profileValidationError(profile: VpnProfile): Int? {
        if (profile.name.isBlank()) return R.string.profile_name_required
        if (!isHttpsOrigin(profile.server)) return R.string.https_required
        if (!isValidToken(profile.token)) {
            return R.string.credentials_required
        }
        return null
    }

    private fun profileStatus(value: String): String = when {
        value.startsWith("Connected") -> getString(R.string.profile_connected)
        value.startsWith("Connection blocked") -> getString(R.string.connection_blocked)
        value.startsWith("Reconnecting") || value.startsWith("Connection lost") ->
            getString(R.string.profile_reconnecting)
        value.startsWith("Waiting") -> getString(R.string.waiting_for_network)
        else -> getString(R.string.profile_connecting)
    }

    private fun dialogField(hintResource: Int, initial: String) = EditText(this).apply {
        setHint(hintResource)
        setText(initial)
        textSize = 15f
        setTextColor(COLOR_TEXT)
        setHintTextColor(COLOR_MUTED)
        background = rounded(COLOR_FIELD, 12f, COLOR_BORDER)
        setPadding(dp(13), 0, dp(13), 0)
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
        isSingleLine = true
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(50))
    }

    private fun dialogLabel(textResource: Int) = TextView(this).apply {
        setText(textResource)
        textSize = 12f
        setTextColor(COLOR_MUTED)
        setTypeface(typeface, Typeface.BOLD)
        setPadding(dp(2), dp(12), 0, dp(6))
    }

    private fun switchThumbColors() = android.content.res.ColorStateList(
        arrayOf(intArrayOf(android.R.attr.state_checked), intArrayOf()),
        intArrayOf(COLOR_ACCENT, COLOR_MUTED),
    )

    private fun switchTrackColors() = android.content.res.ColorStateList(
        arrayOf(intArrayOf(android.R.attr.state_checked), intArrayOf()),
        intArrayOf(COLOR_ACCENT_DARK, COLOR_BORDER),
    )

    private fun statusIntentFilter() = IntentFilter(TunnelService.ACTION_STATUS).apply {
        addAction(TunnelService.ACTION_STATS)
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
            value.startsWith("Waiting") || value.startsWith("Connection blocked")

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    companion object {
        private const val REQUEST_VPN = 100
        private const val REQUEST_NOTIFICATIONS = 101
        private const val REQUEST_QR = 102
        private const val STATE_PENDING_PROFILE = "pending_profile"
        private const val STATUS_PERMISSION = "dev.porta.android.permission.STATUS"

        private val COLOR_BACKGROUND = Color.rgb(8, 17, 31)
        private val COLOR_CARD = Color.rgb(17, 29, 48)
        private val COLOR_FIELD = Color.rgb(11, 23, 40)
        private val COLOR_BORDER = Color.rgb(43, 61, 82)
        private val COLOR_ICON = Color.rgb(25, 52, 65)
        private val COLOR_TEXT = Color.rgb(242, 247, 252)
        private val COLOR_MUTED = Color.rgb(148, 163, 184)
        private val COLOR_ACCENT = Color.rgb(110, 231, 183)
        private val COLOR_ACCENT_DARK = Color.rgb(31, 107, 88)
        private val COLOR_DELETE = Color.rgb(252, 165, 165)
        private val COLOR_DELETE_DARK = Color.rgb(127, 45, 57)
        private val COLOR_UPLOAD = Color.rgb(96, 165, 250)
        private val COLOR_BUTTON_TEXT = Color.rgb(5, 35, 29)
        private val COLOR_CONNECTED = Color.rgb(74, 222, 128)
        private val COLOR_CONNECTING = Color.rgb(250, 204, 21)
        private val COLOR_OFFLINE = Color.rgb(100, 116, 139)
    }
}
