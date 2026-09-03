package dev.htun.android

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val preferences = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
        if (!preferences.getBoolean("auto_connect", false)) return
        val config = SecureTokenStore(context).load() ?: return
        if (VpnService.prepare(context) != null) return
        context.startForegroundService(
            Intent(context, TunnelService::class.java)
                .setAction(TunnelService.ACTION_START)
                .putExtra(TunnelService.EXTRA_SERVER, preferredGateway(config.server))
                .putExtra(TunnelService.EXTRA_TOKEN, config.token)
                .putExtra(TunnelService.EXTRA_CLIENT_ID, config.clientId),
        )
    }
}
