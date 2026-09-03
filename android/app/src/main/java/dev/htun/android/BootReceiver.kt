package dev.htun.android

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
        context.startForegroundService(
            Intent(context, TunnelService::class.java)
                .setAction(TunnelService.ACTION_START)
                .putExtra(TunnelService.EXTRA_PROFILE_ID, config.id)
                .putExtra(TunnelService.EXTRA_PROFILE_NAME, config.name)
                .putExtra(TunnelService.EXTRA_SERVER, preferredGateway(config.server))
                .putExtra(TunnelService.EXTRA_TOKEN, config.token)
                .putExtra(TunnelService.EXTRA_CLIENT_ID, config.clientId),
        )
    }

}
