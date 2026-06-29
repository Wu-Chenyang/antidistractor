package com.antidistractor.ui

import android.app.AppOpsManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.provider.Settings
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.antidistractor.AntidistractorApp
import com.antidistractor.R
import com.antidistractor.blocker.AppBlockerService
import com.antidistractor.model.BlocklistStore
import com.antidistractor.server.ControlServerService
import com.antidistractor.vpn.DnsVpnService

/**
 * MainActivity — 主界面
 *
 * 提供：
 *   1. 权限检查与引导（UsageStats、VPN）
 *   2. 启动/停止 VPN 屏蔽和 App 屏蔽
 *   3. 显示当前状态
 *   4. HTTP 控制服务器状态
 */
class MainActivity : AppCompatActivity() {

    companion object {
        private const val REQUEST_VPN = 1001
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        updateStatus()
        setupButtons()
    }

    override fun onResume() {
        super.onResume()
        // 重新从 SharedPreferences 加载，确保反映 HTTP API 写入的最新状态
        BlocklistStore.loadFlags(this)
        updateStatus()
    }

    // ── UI setup ──────────────────────────────────────────────────────────

    private fun setupButtons() {
        // VPN 屏蔽
        findViewById<Button>(R.id.btn_toggle_vpn).setOnClickListener {
            toggleVpn()
        }

        // App 屏蔽
        findViewById<Button>(R.id.btn_toggle_app_block).setOnClickListener {
            toggleAppBlock()
        }

        // 引导开启 UsageStats 权限
        findViewById<Button>(R.id.btn_usage_stats).setOnClickListener {
            startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
        }
    }

    private fun updateStatus() {
        val hasUsage = AppBlockerService.hasUsageStatsPermission(this)
        val vpnOn = BlocklistStore.vpnEnabled
        val appOn = BlocklistStore.appBlockEnabled
        val blocklist = BlocklistStore.load(this)

        findViewById<TextView>(R.id.tv_status).text = buildString {
            appendLine("── 状态 ──")
            appendLine("UsageStats 权限: ${if (hasUsage) "✅ 已开启" else "❌ 未开启"}")
            appendLine("VPN 屏蔽: ${if (vpnOn) "✅ 运行中" else "⭕ 已停止"}")
            appendLine("App 屏蔽: ${if (appOn) "✅ 运行中" else "⭕ 已停止"}")
            appendLine("HTTP 服务器: localhost:${ControlServerService.PORT}")
            appendLine("")
            appendLine("── 屏蔽列表 ──")
            appendLine("域名: ${blocklist.domains.size} 个")
            appendLine("应用: ${blocklist.packageNames.size} 个")
        }

        findViewById<Button>(R.id.btn_toggle_vpn).text =
            if (vpnOn) "停止 DNS 屏蔽" else "启动 DNS 屏蔽"
        findViewById<Button>(R.id.btn_toggle_app_block).text =
            if (appOn) "停止 App 屏蔽" else "启动 App 屏蔽"
        findViewById<Button>(R.id.btn_usage_stats).isEnabled = !hasUsage
    }

    // ── VPN toggle ────────────────────────────────────────────────────────

    private fun toggleVpn() {
        if (BlocklistStore.vpnEnabled) {
            stopVpn()
        } else {
            // VPN 需要用户确认
            val intent = VpnService.prepare(this)
            if (intent != null) {
                startActivityForResult(intent, REQUEST_VPN)
            } else {
                startVpn()
            }
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN && resultCode == RESULT_OK) {
            startVpn()
        }
    }

    private fun startVpn() {
        startService(Intent(this, DnsVpnService::class.java).apply {
            action = DnsVpnService.ACTION_START
        })
        BlocklistStore.vpnEnabled = true
        BlocklistStore.saveFlags(this)
        updateStatus()
        Toast.makeText(this, "DNS 屏蔽已启动", Toast.LENGTH_SHORT).show()
    }

    private fun stopVpn() {
        startService(Intent(this, DnsVpnService::class.java).apply {
            action = DnsVpnService.ACTION_STOP
        })
        BlocklistStore.vpnEnabled = false
        BlocklistStore.saveFlags(this)
        updateStatus()
        Toast.makeText(this, "DNS 屏蔽已停止", Toast.LENGTH_SHORT).show()
    }

    // ── App block toggle ──────────────────────────────────────────────────

    private fun toggleAppBlock() {
        if (!AppBlockerService.hasUsageStatsPermission(this)) {
            Toast.makeText(this, "请先开启「使用情况访问权限」", Toast.LENGTH_LONG).show()
            startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
            return
        }

        if (BlocklistStore.appBlockEnabled) {
            startService(Intent(this, AppBlockerService::class.java).apply {
                action = AppBlockerService.ACTION_STOP
            })
            BlocklistStore.appBlockEnabled = false
        } else {
            startService(Intent(this, AppBlockerService::class.java).apply {
                action = AppBlockerService.ACTION_START
            })
            BlocklistStore.appBlockEnabled = true
        }
        BlocklistStore.saveFlags(this)
        updateStatus()
    }
}
