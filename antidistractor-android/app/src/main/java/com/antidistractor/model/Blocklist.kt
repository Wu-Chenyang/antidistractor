package com.antidistractor.model

import android.content.Context
import android.content.SharedPreferences
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

/**
 * The current blocklist — domains, package names, and categories.
 * Persisted to SharedPreferences so all Services can read it after restart.
 */
data class Blocklist(
    /** Domains to block via DNS VPN, e.g. "bilibili.com", "tiktok.com" */
    val domains: MutableSet<String> = mutableSetOf(),
    /** App package names to block via UsageStats overlay, e.g. "tv.danmaku.bili" */
    val packageNames: MutableSet<String> = mutableSetOf(),
    /** App category labels to block, e.g. "entertainment", "social" */
    val categories: MutableSet<String> = mutableSetOf(),
) {
    val isEmpty: Boolean get() = domains.isEmpty() && packageNames.isEmpty() && categories.isEmpty()
}

/**
 * Persists Blocklist + enabled state to SharedPreferences.
 * Accessible from all processes via MODE_MULTI_PROCESS (API < 11 compat flag kept for clarity).
 */
object BlocklistStore {

    private const val PREFS_NAME = "antidistractor_prefs"
    private const val KEY_BLOCKLIST = "blocklist"
    private const val KEY_VPN_ENABLED = "vpn_enabled"
    private const val KEY_APP_BLOCK_ENABLED = "app_block_enabled"
    private const val KEY_SHARED_SECRET = "shared_secret"

    private val gson = Gson()

    private fun prefs(ctx: Context): SharedPreferences =
        ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    // ── Blocklist ─────────────────────────────────────────────────────────

    fun load(ctx: Context): Blocklist {
        val json = prefs(ctx).getString(KEY_BLOCKLIST, null) ?: return Blocklist()
        return try {
            gson.fromJson(json, Blocklist::class.java)
        } catch (e: Exception) {
            Blocklist()
        }
    }

    fun save(ctx: Context, blocklist: Blocklist) {
        prefs(ctx).edit().putString(KEY_BLOCKLIST, gson.toJson(blocklist)).apply()
    }

    // ── Feature flags ─────────────────────────────────────────────────────

    var vpnEnabled: Boolean
        get() = _vpnEnabled
        set(value) { _vpnEnabled = value }
    private var _vpnEnabled = false

    var appBlockEnabled: Boolean
        get() = _appBlockEnabled
        set(value) { _appBlockEnabled = value }
    private var _appBlockEnabled = false

    fun loadFlags(ctx: Context) {
        val p = prefs(ctx)
        _vpnEnabled = p.getBoolean(KEY_VPN_ENABLED, false)
        _appBlockEnabled = p.getBoolean(KEY_APP_BLOCK_ENABLED, false)
    }

    fun saveFlags(ctx: Context) {
        prefs(ctx).edit()
            .putBoolean(KEY_VPN_ENABLED, _vpnEnabled)
            .putBoolean(KEY_APP_BLOCK_ENABLED, _appBlockEnabled)
            .apply()
    }

    // ── Shared secret ─────────────────────────────────────────────────────

    fun getSharedSecret(ctx: Context): String =
        prefs(ctx).getString(KEY_SHARED_SECRET, "") ?: ""

    fun setSharedSecret(ctx: Context, secret: String) {
        prefs(ctx).edit().putString(KEY_SHARED_SECRET, secret).apply()
    }
}
