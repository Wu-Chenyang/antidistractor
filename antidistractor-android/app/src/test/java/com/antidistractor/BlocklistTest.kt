package com.antidistractor

import com.antidistractor.model.Blocklist
import org.junit.Assert.*
import org.junit.Test

class BlocklistTest {

    @Test
    fun `empty blocklist is empty`() {
        assertTrue(Blocklist().isEmpty)
    }

    @Test
    fun `blocklist with domains is not empty`() {
        val b = Blocklist(domains = mutableSetOf("bilibili.com"))
        assertFalse(b.isEmpty)
    }

    @Test
    fun `domain suffix matching`() {
        val blocked = setOf("bilibili.com")
        fun isBlocked(domain: String): Boolean {
            val lower = domain.lowercase().trimEnd('.')
            return blocked.any { b -> lower == b || lower.endsWith(".$b") }
        }
        assertTrue(isBlocked("bilibili.com"))
        assertTrue(isBlocked("api.bilibili.com"))
        assertTrue(isBlocked("live.bilibili.com"))
        assertFalse(isBlocked("notbilibili.com"))
        assertFalse(isBlocked("github.com"))
    }

    @Test
    fun `domain matching is case insensitive`() {
        val blocked = setOf("bilibili.com")
        fun isBlocked(domain: String): Boolean {
            val lower = domain.lowercase().trimEnd('.')
            return blocked.any { b -> lower == b || lower.endsWith(".$b") }
        }
        assertTrue(isBlocked("BILIBILI.COM"))
        assertTrue(isBlocked("Api.Bilibili.Com"))
    }

    @Test
    fun `trailing dot is trimmed`() {
        val blocked = setOf("bilibili.com")
        fun isBlocked(domain: String): Boolean {
            val lower = domain.lowercase().trimEnd('.')
            return blocked.any { b -> lower == b || lower.endsWith(".$b") }
        }
        assertTrue(isBlocked("bilibili.com."))
        assertTrue(isBlocked("api.bilibili.com."))
    }
}
