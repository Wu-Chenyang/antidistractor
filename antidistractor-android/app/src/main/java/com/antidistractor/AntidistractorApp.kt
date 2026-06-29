package com.antidistractor

import android.app.Application
import android.content.Intent
import com.antidistractor.model.BlocklistStore
import com.antidistractor.server.ControlServerService
import com.antidistractor.vpn.DnsVpnService
import com.antidistractor.blocker.AppBlockerService

class AntidistractorApp : Application() {

    override fun onCreate() {
        super.onCreate()

        // Load persisted flags
        BlocklistStore.loadFlags(this)

        // Always start the HTTP control server
        startService(Intent(this, ControlServerService::class.java).apply {
            action = ControlServerService.ACTION_START
        })

        // Restore previously active services
        if (BlocklistStore.vpnEnabled) {
            startService(Intent(this, DnsVpnService::class.java).apply {
                action = DnsVpnService.ACTION_START
            })
        }
        if (BlocklistStore.appBlockEnabled) {
            startService(Intent(this, AppBlockerService::class.java).apply {
                action = AppBlockerService.ACTION_START
            })
        }
    }
}
