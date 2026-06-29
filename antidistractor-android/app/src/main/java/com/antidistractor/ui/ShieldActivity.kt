package com.antidistractor.ui

import android.app.Activity
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.WindowManager
import android.widget.Button
import android.widget.TextView
import com.antidistractor.R

/**
 * ShieldActivity — 屏蔽覆盖层
 *
 * 当 AppBlockerService 检测到被屏蔽的 App 进入前台时，
 * 立刻启动此 Activity 覆盖在其上方，显示屏蔽提示。
 *
 * 设计：
 *   - 全屏深色背景，无标题栏
 *   - 显示被屏蔽 App 的名称
 *   - 只有一个按钮：返回主屏幕
 *   - 不允许返回键回到被屏蔽的 App
 */
class ShieldActivity : Activity() {

    companion object {
        const val EXTRA_BLOCKED_PACKAGE = "blocked_package"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 全屏，覆盖状态栏
        window.addFlags(
            WindowManager.LayoutParams.FLAG_FULLSCREEN or
            WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON
        )

        setContentView(R.layout.activity_shield)

        val blockedPackage = intent.getStringExtra(EXTRA_BLOCKED_PACKAGE) ?: ""
        val appName = getAppName(blockedPackage)

        findViewById<TextView>(R.id.tv_app_name).text = appName
        findViewById<TextView>(R.id.tv_message).text = "此应用在专注时段已被屏蔽"

        // 返回主屏幕按钮
        findViewById<Button>(R.id.btn_go_home).setOnClickListener {
            goHome()
        }
    }

    override fun onBackPressed() {
        // 禁用返回键，防止用户返回被屏蔽的 App
        goHome()
    }

    override fun onNewIntent(intent: android.content.Intent?) {
        super.onNewIntent(intent)
        // 更新显示的 App 名称（同一个 ShieldActivity 实例被复用时）
        val blockedPackage = intent?.getStringExtra(EXTRA_BLOCKED_PACKAGE) ?: ""
        if (blockedPackage.isNotEmpty()) {
            findViewById<TextView>(R.id.tv_app_name)?.text = getAppName(blockedPackage)
        }
    }

    private fun goHome() {
        val homeIntent = android.content.Intent(android.content.Intent.ACTION_MAIN).apply {
            addCategory(android.content.Intent.CATEGORY_HOME)
            flags = android.content.Intent.FLAG_ACTIVITY_NEW_TASK
        }
        startActivity(homeIntent)
        finish()
    }

    private fun getAppName(packageName: String): String {
        return try {
            val info = packageManager.getApplicationInfo(packageName, 0)
            packageManager.getApplicationLabel(info).toString()
        } catch (e: PackageManager.NameNotFoundException) {
            packageName
        }
    }
}
