package com.antidistractor.blocker

import android.app.*
import android.app.usage.UsageStatsManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.antidistractor.model.BlocklistStore
import com.antidistractor.ui.MainActivity
import com.antidistractor.ui.ShieldActivity

/**
 * AppBlockerService — 方案C：UsageStats + 覆盖层实现 App 屏蔽
 *
 * 原理：
 *   1. 每 500ms 查询一次当前前台 App（UsageStatsManager）
 *   2. 如果前台 App 在屏蔽列表中，立刻启动 ShieldActivity 覆盖它
 *   3. ShieldActivity 全屏显示"已屏蔽"界面，用户无法操作被屏蔽的 App
 *
 * 权限要求：
 *   - PACKAGE_USAGE_STATS（特殊权限，需引导用户在设置中手动开启）
 *   - FOREGROUND_SERVICE（后台长期运行）
 *
 * 局限：
 *   - 约 500ms 内用户可短暂看到被屏蔽 App 的内容
 *   - 用户可以在设置中强制停止此 Service
 */
class AppBlockerService : Service() {

    companion object {
        private const val TAG = "AppBlockerService"
        const val ACTION_START = "com.antidistractor.blocker.START"
        const val ACTION_STOP = "com.antidistractor.blocker.STOP"
        const val NOTIFICATION_ID = 1002
        const val CHANNEL_ID = "antidistractor_blocker"

        /** 轮询间隔（毫秒） */
        private const val POLL_INTERVAL_MS = 500L

        /** 检查应用是否有 UsageStats 权限 */
        fun hasUsageStatsPermission(ctx: Context): Boolean {
            val appOps = ctx.getSystemService(Context.APP_OPS_SERVICE) as android.app.AppOpsManager
            val mode = appOps.unsafeCheckOpNoThrow(
                android.app.AppOpsManager.OPSTR_GET_USAGE_STATS,
                android.os.Process.myUid(),
                ctx.packageName
            )
            return mode == android.app.AppOpsManager.MODE_ALLOWED
        }
    }

    private val handler = Handler(Looper.getMainLooper())
    private var isRunning = false

    // 当前屏蔽的包名集合
    @Volatile
    private var blockedPackages: Set<String> = emptySet()

    // 上一次前台 App，避免重复触发
    @Volatile
    private var lastForegroundPackage: String = ""

    // 监听 blocklist 更新广播
    private val blocklistReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == com.antidistractor.server.ControlServerService.ACTION_BLOCKLIST_UPDATED) {
                val updated = BlocklistStore.load(context)
                blockedPackages = updated.packageNames.toSet()
                Log.i(TAG, "Blocklist updated via broadcast: ${blockedPackages.size} packages")
            }
        }
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startBlocking()
            ACTION_STOP  -> stopBlocking()
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?) = null

    override fun onDestroy() {
        stopBlocking()
        unregisterReceiver(blocklistReceiver)
        super.onDestroy()
    }

    // ── Blocking control ──────────────────────────────────────────────────

    private fun startBlocking() {
        if (isRunning) return

        // Load blocklist
        val blocklist = BlocklistStore.load(this)
        blockedPackages = blocklist.packageNames.toSet()
        Log.i(TAG, "AppBlocker starting, blocking ${blockedPackages.size} packages")

        // 注册广播接收器，监听 blocklist 更新
        val filter = android.content.IntentFilter(
            com.antidistractor.server.ControlServerService.ACTION_BLOCKLIST_UPDATED
        )
        registerReceiver(blocklistReceiver, filter, RECEIVER_NOT_EXPORTED)

        startForeground(NOTIFICATION_ID, buildNotification())
        isRunning = true
        scheduleNextCheck()
    }

    private fun stopBlocking() {
        isRunning = false
        handler.removeCallbacksAndMessages(null)
        stopForeground(STOP_FOREGROUND_REMOVE)
        Log.i(TAG, "AppBlocker stopped")
    }

    /** Update the blocked package list at runtime. */
    fun updateBlocklist(packages: Set<String>) {
        blockedPackages = packages
        Log.i(TAG, "AppBlocker blocklist updated: ${packages.size} packages")
    }

    // ── Polling loop ──────────────────────────────────────────────────────

    private fun scheduleNextCheck() {
        if (!isRunning) return
        handler.postDelayed({
            checkForegroundApp()
            scheduleNextCheck()
        }, POLL_INTERVAL_MS)
    }

    private fun checkForegroundApp() {
        val foreground = getForegroundPackage() ?: return

        // Ignore our own app and the shield activity
        if (foreground == packageName) return

        if (isBlocked(foreground)) {
            if (foreground != lastForegroundPackage) {
                Log.i(TAG, "Blocked app in foreground: $foreground")
                lastForegroundPackage = foreground
                showShield(foreground)
            }
        } else {
            if (lastForegroundPackage.isNotEmpty() && foreground != packageName) {
                lastForegroundPackage = ""
            }
        }
    }

    /**
     * Get the current foreground app's package name.
     * Uses UsageStatsManager.queryUsageStats() — requires PACKAGE_USAGE_STATS permission.
     */
    private fun getForegroundPackage(): String? {
        val usm = getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
        val now = System.currentTimeMillis()
        val stats = usm.queryUsageStats(
            UsageStatsManager.INTERVAL_DAILY,
            now - 5000,  // last 5 seconds
            now
        ) ?: return null

        return stats
            .filter { it.lastTimeUsed > 0 }
            .maxByOrNull { it.lastTimeUsed }
            ?.packageName
    }

    private fun isBlocked(packageName: String): Boolean {
        // 精确匹配
        if (blockedPackages.contains(packageName)) return true
        // 前缀通配符：pattern 以 '*' 结尾，匹配包名前缀
        // 例如 "tv.danmaku.*" 匹配 "tv.danmaku.bili"、"tv.danmaku.bilibilihd" 等
        return blockedPackages.any { pattern ->
            pattern.endsWith('*') && packageName.startsWith(pattern.dropLast(1))
        }
    }

    /** Launch ShieldActivity to cover the blocked app. */
    private fun showShield(blockedPackage: String) {
        val intent = Intent(this, ShieldActivity::class.java).apply {
            addFlags(
                Intent.FLAG_ACTIVITY_NEW_TASK or
                Intent.FLAG_ACTIVITY_CLEAR_TOP or
                Intent.FLAG_ACTIVITY_SINGLE_TOP
            )
            putExtra(ShieldActivity.EXTRA_BLOCKED_PACKAGE, blockedPackage)
        }
        startActivity(intent)
    }

    // ── Notification ──────────────────────────────────────────────────────

    private fun buildNotification(): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "App 屏蔽服务", NotificationManager.IMPORTANCE_LOW)
                    .apply { description = "Antidistractor App 屏蔽运行中" }
            )
        }
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Antidistractor")
            .setContentText("App 屏蔽运行中")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }
}
