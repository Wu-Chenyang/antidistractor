package com.antidistractor.server

import android.app.*
import android.content.Intent
import android.util.Log
import com.antidistractor.blocker.AppBlockerService
import com.antidistractor.model.Blocklist
import com.antidistractor.model.BlocklistStore
import com.antidistractor.ui.MainActivity
import com.antidistractor.vpn.DnsVpnService
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import kotlinx.coroutines.*
import java.io.*
import java.net.ServerSocket
import java.net.Socket

/**
 * ControlServerService — 本地 HTTP 控制服务器
 *
 * 监听 localhost:18964，提供与 iOS 端完全一致的 REST API：
 *   POST /block    { "domains": [...], "package_names": [...] }
 *   POST /unblock  { "domains": [...], "package_names": [...] }
 *   POST /clear    {}
 *   GET  /status   → { "ok": true, "vpn_enabled": bool, ... }
 *
 * 通过 X-Antidistractor-Secret 请求头进行身份验证。
 */
class ControlServerService : Service() {

    companion object {
        private const val TAG = "ControlServer"
        const val PORT = 18964
        const val NOTIFICATION_ID = 1003
        const val CHANNEL_ID = "antidistractor_server"
        const val ACTION_START = "com.antidistractor.server.START"
        const val ACTION_STOP = "com.antidistractor.server.STOP"
        const val ACTION_BLOCKLIST_UPDATED = "com.antidistractor.BLOCKLIST_UPDATED"
    }

    private val gson = Gson()
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var serverSocket: ServerSocket? = null

    // ── Lifecycle ─────────────────────────────────────────────────────────

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startServer()
            ACTION_STOP  -> stopServer()
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?) = null

    override fun onDestroy() {
        stopServer()
        scope.cancel()
        super.onDestroy()
    }

    // ── Server ────────────────────────────────────────────────────────────

    private fun startServer() {
        startForeground(NOTIFICATION_ID, buildNotification())
        scope.launch {
            try {
                serverSocket = ServerSocket(PORT, 50,
                    java.net.InetAddress.getByName("127.0.0.1"))
                Log.i(TAG, "Control server listening on localhost:$PORT")
                while (isActive) {
                    val client = serverSocket?.accept() ?: break
                    launch { handleClient(client) }
                }
            } catch (e: Exception) {
                if (isActive) Log.e(TAG, "Server error: ${e.message}")
            }
        }
    }

    private fun stopServer() {
        serverSocket?.close()
        serverSocket = null
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    // ── Request handling ──────────────────────────────────────────────────

    private fun handleClient(socket: Socket) {
        socket.use {
            try {
                val reader = BufferedReader(InputStreamReader(socket.getInputStream()))
                val writer = socket.getOutputStream()

                // Read request line + headers
                val requestLine = reader.readLine() ?: return
                val parts = requestLine.split(" ")
                if (parts.size < 2) return
                val method = parts[0]
                val path = parts[1]

                val headers = mutableMapOf<String, String>()
                var line = reader.readLine()
                while (!line.isNullOrEmpty()) {
                    val colon = line.indexOf(':')
                    if (colon > 0) {
                        headers[line.substring(0, colon).lowercase().trim()] =
                            line.substring(colon + 1).trim()
                    }
                    line = reader.readLine()
                }

                // Auth check
                val secret = BlocklistStore.getSharedSecret(this)
                if (secret.isNotEmpty()) {
                    val token = headers["x-antidistractor-secret"] ?: ""
                    if (token != secret) {
                        sendResponse(writer, 401, ControlResponse(ok = false, error = "unauthorized"))
                        return
                    }
                }

                // Read body
                val contentLength = headers["content-length"]?.toIntOrNull() ?: 0
                val bodyChars = CharArray(contentLength)
                if (contentLength > 0) reader.read(bodyChars)
                val body = String(bodyChars)

                // Route
                val response = when {
                    method == "POST" && path == "/block"   -> handleBlock(body)
                    method == "POST" && path == "/unblock" -> handleUnblock(body)
                    method == "POST" && path == "/clear"   -> handleClear()
                    method == "POST" && path == "/sync"    -> handleSync(body)
                    method == "GET"  && path == "/status"  -> handleStatus()
                    else -> ControlResponse(ok = false, error = "unknown: $method $path")
                }

                sendResponse(writer, if (response.ok) 200 else 400, response)
            } catch (e: Exception) {
                Log.w(TAG, "Client error: ${e.message}")
            }
        }
    }

    // ── Handlers ──────────────────────────────────────────────────────────

    private fun handleBlock(body: String): ControlResponse {
        val req = try {
            gson.fromJson(body, ControlRequest::class.java)
        } catch (e: Exception) {
            return ControlResponse(ok = false, error = "invalid JSON")
        }

        val blocklist = BlocklistStore.load(this)
        req.domains?.let { blocklist.domains.addAll(it) }
        req.packageNames?.let { blocklist.packageNames.addAll(it) }
        req.categories?.let { blocklist.categories.addAll(it) }
        BlocklistStore.save(this, blocklist)

        // Notify running services
        notifyServicesUpdated(blocklist)

        Log.i(TAG, "Block: +${req.domains?.size ?: 0} domains, +${req.packageNames?.size ?: 0} packages")
        return ControlResponse(ok = true)
    }

    private fun handleUnblock(body: String): ControlResponse {
        val req = try {
            gson.fromJson(body, ControlRequest::class.java)
        } catch (e: Exception) {
            return ControlResponse(ok = false, error = "invalid JSON")
        }

        val blocklist = BlocklistStore.load(this)
        req.domains?.let { blocklist.domains.removeAll(it.toSet()) }
        req.packageNames?.let { blocklist.packageNames.removeAll(it.toSet()) }
        BlocklistStore.save(this, blocklist)

        notifyServicesUpdated(blocklist)

        return ControlResponse(ok = true)
    }

    private fun handleClear(): ControlResponse {
        val empty = Blocklist()
        BlocklistStore.save(this, empty)
        notifyServicesUpdated(empty)
        return ControlResponse(ok = true)
    }

    /**
     * 原子替换屏蔽集合（与 Linux/macOS sync 命令语义一致）。
     * 先清空现有屏蔽，再批量写入新集合，一次广播通知所有 Service 更新。
     * 支持通配符包名（如 "tv.danmaku.*"），由 AppBlockerService.isBlocked 负责匹配。
     */
    private fun handleSync(body: String): ControlResponse {
        val req = try {
            gson.fromJson(body, ControlRequest::class.java)
        } catch (e: Exception) {
            return ControlResponse(ok = false, error = "invalid JSON")
        }
        val fresh = Blocklist(
            domains      = (req.domains      ?: emptyList()).toMutableSet(),
            packageNames = (req.packageNames ?: emptyList()).toMutableSet(),
            categories   = (req.categories   ?: emptyList()).toMutableSet(),
        )
        BlocklistStore.save(this, fresh)
        notifyServicesUpdated(fresh)
        Log.i(TAG, "Sync: ${fresh.domains.size} domains, ${fresh.packageNames.size} packages")
        return ControlResponse(ok = true)
    }

    private fun handleStatus(): ControlResponse {
        val blocklist = BlocklistStore.load(this)
        return ControlResponse(
            ok = true,
            vpnEnabled = BlocklistStore.vpnEnabled,
            appBlockEnabled = BlocklistStore.appBlockEnabled,
            blocklist = BlocklistPayload(
                domains = blocklist.domains.sorted(),
                packageNames = blocklist.packageNames.sorted(),
                categories = blocklist.categories.sorted()
            )
        )
    }

    /**
     * Notify running services about blocklist changes via broadcast.
     * Services listen for this broadcast and update their in-memory state.
     */
    private fun notifyServicesUpdated(blocklist: Blocklist) {
        val intent = Intent(ACTION_BLOCKLIST_UPDATED).apply {
            setPackage(packageName)
        }
        sendBroadcast(intent)
    }

    // ── HTTP response ─────────────────────────────────────────────────────

    private fun sendResponse(out: OutputStream, status: Int, body: ControlResponse) {
        val json = gson.toJson(body)
        val response = buildString {
            append("HTTP/1.1 $status ${if (status == 200) "OK" else "Error"}\r\n")
            append("Content-Type: application/json\r\n")
            append("Content-Length: ${json.toByteArray().size}\r\n")
            append("Connection: close\r\n")
            append("\r\n")
            append(json)
        }
        out.write(response.toByteArray())
        out.flush()
    }

    // ── Notification ──────────────────────────────────────────────────────

    private fun buildNotification(): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "控制服务器", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Antidistractor")
            .setContentText("控制服务器运行中 (localhost:$PORT)")
            .setSmallIcon(android.R.drawable.ic_menu_manage)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

}

// ── Data classes ──────────────────────────────────────────────────────────────

data class ControlRequest(
    val domains: List<String>? = null,
    @SerializedName("package_names") val packageNames: List<String>? = null,
    val categories: List<String>? = null,
)

data class ControlResponse(
    val ok: Boolean,
    val error: String? = null,
    @SerializedName("vpn_enabled") val vpnEnabled: Boolean? = null,
    @SerializedName("app_block_enabled") val appBlockEnabled: Boolean? = null,
    val blocklist: BlocklistPayload? = null,
)

data class BlocklistPayload(
    val domains: List<String>,
    @SerializedName("package_names") val packageNames: List<String>,
    val categories: List<String>,
)
