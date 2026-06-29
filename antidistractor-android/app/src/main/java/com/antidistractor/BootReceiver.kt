package com.antidistractor

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.antidistractor.model.BlocklistStore
import com.antidistractor.server.ControlServerService
import com.antidistractor.vpn.DnsVpnService
import com.antidistractor.blocker.AppBlockerService

/** 开机自启：恢复上次运行状态 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED &&
            intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return

        BlocklistStore.loadFlags(context)

        // 始终启动控制服务器
        context.startForegroundService(
            Intent(context, ControlServerService::class.java).apply {
                action = ControlServerService.ACTION_START
            }
        )

        if (BlocklistStore.vpnEnabled) {
            context.startForegroundService(
                Intent(context, DnsVpnService::class.java).apply {
                    action = DnsVpnService.ACTION_START
                }
            )
        }

        if (BlocklistStore.appBlockEnabled) {
            context.startForegroundService(
                Intent(context, AppBlockerService::class.java).apply {
                    action = AppBlockerService.ACTION_START
                }
            )
        }
    }
}
