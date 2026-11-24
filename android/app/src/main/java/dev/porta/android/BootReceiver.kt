package dev.porta.android

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val profiles = VpnProfileStore(context)
        val config = profiles.profiles().firstOrNull { it.autoConnect } ?: return
        if (VpnService.prepare(context) != null) return
        profiles.select(config.id)
        // The same intent as the app's, so backup gateways and profile
        // options survive a restart.
        context.startForegroundService(TunnelService.startIntent(context, config))
    }

}
