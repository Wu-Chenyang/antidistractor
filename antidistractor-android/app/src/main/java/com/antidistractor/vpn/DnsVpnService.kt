package com.antidistractor.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import com.antidistractor.model.BlocklistStore
import com.antidistractor.ui.MainActivity
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer

/**
 * DnsVpnService — 方案A：本地 VPN 实现域名/网站屏蔽
 *
 * 原理：
 *   1. 建立本地 TUN 虚拟网卡，拦截所有 DNS 查询（UDP 53 端口）
 *   2. 对被屏蔽域名返回 127.0.0.1，其他查询转发到真实 DNS 服务器
 *   3. 其余流量（非 DNS）直接放行，不影响正常网络
 *
 * 优点：
 *   - 无需 root
 *   - 屏蔽所有 App 的网络请求（浏览器、B站、抖音等）
 *   - 用户只需确认一次 VPN 弹窗
 *
 * 缺点：
 *   - 与其他 VPN/代理冲突（同时只能运行一个 VPN）
 *   - 可被绕过：App 使用硬编码 IP 或 DoH（DNS over HTTPS）
 */
class DnsVpnService : VpnService() {

    companion object {
        private const val TAG = "DnsVpnService"
        const val ACTION_START = "com.antidistractor.vpn.START"
        const val ACTION_STOP = "com.antidistractor.vpn.STOP"
        const val NOTIFICATION_ID = 1001
        const val CHANNEL_ID = "antidistractor_vpn"

        /** 上游 DNS 服务器（用于转发非屏蔽域名的查询） */
        private const val UPSTREAM_DNS = "8.8.8.8"
        private const val UPSTREAM_DNS_PORT = 53

        /** TUN 接口地址（虚拟，不与真实网络冲突） */
        private const val TUN_ADDRESS = "10.0.0.1"
        private const val TUN_PREFIX_LENGTH = 24

        /** 我们的虚假 DNS 服务器地址（TUN 网段内） */
        private const val FAKE_DNS = "10.0.0.2"
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var serviceJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // 当前被屏蔽的域名集合（从 BlocklistStore 加载）
    @Volatile
    private var blockedDomains: Set<String> = emptySet()

    // ── Lifecycle ─────────────────────────────────────────────────────────

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startVpn()
            ACTION_STOP  -> stopVpn()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopVpn()
        scope.cancel()
        super.onDestroy()
    }

    // ── VPN control ───────────────────────────────────────────────────────

    private fun startVpn() {
        if (vpnInterface != null) return  // already running

        // Load blocklist
        val blocklist = BlocklistStore.load(this)
        blockedDomains = blocklist.domains.toSet()
        Log.i(TAG, "Starting VPN, blocking ${blockedDomains.size} domains")

        // Build VPN interface
        val builder = Builder()
            .setSession("Antidistractor")
            .addAddress(TUN_ADDRESS, TUN_PREFIX_LENGTH)
            // Route only DNS traffic through the VPN (10.0.0.2 = our fake DNS)
            .addRoute(FAKE_DNS, 32)
            // Set our fake DNS as the DNS server for the device
            .addDnsServer(FAKE_DNS)
            .setMtu(1500)
            .setBlocking(false)

        // Exclude ourselves from the VPN to avoid routing loops
        builder.addDisallowedApplication(packageName)

        vpnInterface = builder.establish() ?: run {
            Log.e(TAG, "Failed to establish VPN interface")
            return
        }

        startForeground(NOTIFICATION_ID, buildNotification())

        // Start packet processing loop
        serviceJob = scope.launch {
            processPackets()
        }

        Log.i(TAG, "VPN started, fake DNS at $FAKE_DNS")
    }

    private fun stopVpn() {
        serviceJob?.cancel()
        serviceJob = null
        vpnInterface?.close()
        vpnInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        Log.i(TAG, "VPN stopped")
    }

    /** Update the blocked domains list at runtime (called by ControlServerService). */
    fun updateBlocklist(domains: Set<String>) {
        blockedDomains = domains
        Log.i(TAG, "Blocklist updated: ${domains.size} domains")
    }

    // ── Packet processing ─────────────────────────────────────────────────

    /**
     * Read IP packets from the TUN interface.
     * We only care about UDP packets destined for our fake DNS (10.0.0.2:53).
     * Everything else is written back to the TUN as-is (pass-through).
     */
    private suspend fun processPackets() = withContext(Dispatchers.IO) {
        val fd = vpnInterface?.fileDescriptor ?: return@withContext
        val inputStream = FileInputStream(fd)
        val outputStream = FileOutputStream(fd)
        val buffer = ByteBuffer.allocate(32767)

        while (isActive) {
            buffer.clear()
            val length = try {
                inputStream.read(buffer.array())
            } catch (e: Exception) {
                if (isActive) Log.e(TAG, "Read error: ${e.message}")
                break
            }

            if (length <= 0) {
                delay(1)
                continue
            }

            buffer.limit(length)

            // Parse IP header to check if this is UDP to our fake DNS
            if (isDnsQuery(buffer, length)) {
                // Extract DNS payload and handle it
                val dnsPayload = extractDnsPayload(buffer, length)
                if (dnsPayload != null) {
                    val response = handleDnsQuery(dnsPayload)
                    if (response != null) {
                        // Build IP+UDP response packet and write back to TUN
                        val responsePacket = buildIpUdpPacket(
                            srcIp = FAKE_DNS,
                            dstIp = TUN_ADDRESS,
                            srcPort = UPSTREAM_DNS_PORT,
                            dstPort = extractSourcePort(buffer, length),
                            payload = response
                        )
                        outputStream.write(responsePacket)
                        continue
                    }
                }
            }

            // Pass-through: write packet back unchanged
            outputStream.write(buffer.array(), 0, length)
        }
    }

    /**
     * Check if the packet is a UDP DNS query to our fake DNS server.
     * IPv4 only (we don't add IPv6 routes so IPv6 DNS won't come through).
     */
    private fun isDnsQuery(buf: ByteBuffer, length: Int): Boolean {
        if (length < 28) return false  // min IP(20) + UDP(8)
        val ipVersion = (buf[0].toInt() and 0xF0) shr 4
        if (ipVersion != 4) return false
        val protocol = buf[9].toInt() and 0xFF
        if (protocol != 17) return false  // 17 = UDP
        val ihl = (buf[0].toInt() and 0x0F) * 4
        val dstIp = "${buf[ihl + 16].toInt() and 0xFF}.${buf[ihl + 17].toInt() and 0xFF}" +
                    ".${buf[ihl + 18].toInt() and 0xFF}.${buf[ihl + 19].toInt() and 0xFF}"
        // Destination should be our fake DNS
        if (dstIp != FAKE_DNS.split(".").let {
                "${it[0]}.${it[1]}.${it[2]}.${it[3]}"
            }) return false
        val dstPort = ((buf[ihl + 22].toInt() and 0xFF) shl 8) or (buf[ihl + 23].toInt() and 0xFF)
        return dstPort == 53
    }

    private fun extractDnsPayload(buf: ByteBuffer, length: Int): ByteArray? {
        val ihl = (buf[0].toInt() and 0x0F) * 4
        val udpStart = ihl
        val dnsStart = udpStart + 8
        if (dnsStart >= length) return null
        return buf.array().copyOfRange(dnsStart, length)
    }

    private fun extractSourcePort(buf: ByteBuffer, length: Int): Int {
        val ihl = (buf[0].toInt() and 0x0F) * 4
        return ((buf[ihl].toInt() and 0xFF) shl 8) or (buf[ihl + 1].toInt() and 0xFF)
    }

    /**
     * Handle a DNS query:
     * - If the queried domain is in the blocklist → return 127.0.0.1
     * - Otherwise → forward to upstream DNS and return the real response
     */
    private suspend fun handleDnsQuery(dnsPayload: ByteArray): ByteArray? =
        withContext(Dispatchers.IO) {
            val queriedDomain = parseDnsQueryDomain(dnsPayload) ?: return@withContext null

            Log.d(TAG, "DNS query: $queriedDomain")

            if (isBlocked(queriedDomain)) {
                Log.i(TAG, "Blocked: $queriedDomain → 127.0.0.1")
                return@withContext buildBlockedDnsResponse(dnsPayload)
            }

            // Forward to upstream DNS
            return@withContext forwardDnsQuery(dnsPayload)
        }

    /**
     * Check if a domain (or any of its parent domains) is in the blocklist.
     * e.g. "api.bilibili.com" matches if "bilibili.com" is blocked.
     */
    private fun isBlocked(domain: String): Boolean {
        val lower = domain.lowercase().trimEnd('.')
        return blockedDomains.any { blocked ->
            lower == blocked || lower.endsWith(".$blocked")
        }
    }

    /** Parse the queried domain name from a DNS query packet. */
    private fun parseDnsQueryDomain(dns: ByteArray): String? {
        return try {
            // DNS header is 12 bytes; question section starts at offset 12
            var offset = 12
            val sb = StringBuilder()
            while (offset < dns.size) {
                val len = dns[offset].toInt() and 0xFF
                if (len == 0) break
                if (sb.isNotEmpty()) sb.append('.')
                offset++
                repeat(len) {
                    sb.append(dns[offset++].toChar())
                }
            }
            sb.toString().lowercase()
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Build a DNS response that resolves the queried domain to 127.0.0.1.
     * Constructs a minimal valid DNS A record response.
     */
    private fun buildBlockedDnsResponse(query: ByteArray): ByteArray {
        val response = query.copyOf(query.size + 16)
        // Set QR=1 (response), AA=1, RCODE=0
        response[2] = (0x81).toByte()
        response[3] = (0x80).toByte()
        // ANCOUNT = 1
        response[6] = 0
        response[7] = 1

        // Find end of question section
        var offset = 12
        while (offset < query.size && query[offset] != 0.toByte()) {
            offset += (query[offset].toInt() and 0xFF) + 1
        }
        offset += 5  // skip null terminator + QTYPE(2) + QCLASS(2)

        // Append answer: pointer to name (0xC00C), TYPE A, CLASS IN, TTL 1, RDLENGTH 4, 127.0.0.1
        val answer = byteArrayOf(
            0xC0.toByte(), 0x0C.toByte(),  // name pointer to offset 12
            0x00, 0x01,                     // TYPE A
            0x00, 0x01,                     // CLASS IN
            0x00, 0x00, 0x00, 0x01,         // TTL = 1 second
            0x00, 0x04,                     // RDLENGTH = 4
            127, 0, 0, 1                    // 127.0.0.1
        )

        return query.copyOfRange(0, offset) + answer
    }

    /** Forward DNS query to upstream server and return the response. */
    private fun forwardDnsQuery(query: ByteArray): ByteArray? {
        return try {
            DatagramSocket().use { socket ->
                socket.soTimeout = 3000
                val upstream = InetAddress.getByName(UPSTREAM_DNS)
                val request = DatagramPacket(query, query.size, upstream, UPSTREAM_DNS_PORT)
                socket.send(request)
                val responseBuffer = ByteArray(4096)
                val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
                socket.receive(responsePacket)
                responseBuffer.copyOfRange(0, responsePacket.length)
            }
        } catch (e: Exception) {
            Log.w(TAG, "DNS forward failed for query: ${e.message}")
            null
        }
    }

    /**
     * Wrap a DNS payload in an IPv4 + UDP packet for writing back to the TUN interface.
     */
    private fun buildIpUdpPacket(
        srcIp: String, dstIp: String,
        srcPort: Int, dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val udpLength = 8 + payload.size
        val ipLength = 20 + udpLength
        val packet = ByteArray(ipLength)

        // IPv4 header
        packet[0] = 0x45.toByte()           // Version=4, IHL=5
        packet[1] = 0                        // DSCP/ECN
        packet[2] = (ipLength shr 8).toByte()
        packet[3] = (ipLength and 0xFF).toByte()
        packet[4] = 0; packet[5] = 0        // Identification
        packet[6] = 0x40.toByte()           // Don't fragment
        packet[7] = 0
        packet[8] = 64                       // TTL
        packet[9] = 17                       // Protocol = UDP
        // Checksum (10-11) — calculated below
        srcIp.split(".").map { it.toInt() }.forEachIndexed { i, b -> packet[12 + i] = b.toByte() }
        dstIp.split(".").map { it.toInt() }.forEachIndexed { i, b -> packet[16 + i] = b.toByte() }

        // IP checksum
        val ipChecksum = ipChecksum(packet, 0, 20)
        packet[10] = (ipChecksum shr 8).toByte()
        packet[11] = (ipChecksum and 0xFF).toByte()

        // UDP header
        packet[20] = (srcPort shr 8).toByte()
        packet[21] = (srcPort and 0xFF).toByte()
        packet[22] = (dstPort shr 8).toByte()
        packet[23] = (dstPort and 0xFF).toByte()
        packet[24] = (udpLength shr 8).toByte()
        packet[25] = (udpLength and 0xFF).toByte()
        packet[26] = 0; packet[27] = 0     // UDP checksum (optional for IPv4)

        // DNS payload
        payload.copyInto(packet, 28)

        return packet
    }

    private fun ipChecksum(buf: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        while (i < offset + length - 1) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i += 2
        }
        if ((length and 1) != 0) sum += (buf[offset + length - 1].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.inv() and 0xFFFF
    }

    // ── Notification ──────────────────────────────────────────────────────

    private fun buildNotification(): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "VPN 屏蔽服务", NotificationManager.IMPORTANCE_LOW)
                    .apply { description = "Antidistractor DNS 屏蔽运行中" }
            )
        }
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Antidistractor")
            .setContentText("DNS 屏蔽运行中")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }
}
