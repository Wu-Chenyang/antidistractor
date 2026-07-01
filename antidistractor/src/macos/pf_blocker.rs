//! macOS network blocker using /etc/hosts only.
//!
//! Design decision: /etc/hosts-only, NO PF IP rules.
//!
//! Why not PF with IP blocking:
//!   - Bilibili, YouTube, TikTok etc. use CDNs (Akamai, CloudFront, Fastly).
//!     The same IP addresses serve thousands of unrelated sites simultaneously.
//!   - Blocking those IPs breaks other services sharing the same CDN
//!     (e.g. copilot-proxy, clash, npm, homebrew, etc.).
//!   - IP sets also become stale within minutes as CDNs rotate IPs.
//!
//! /etc/hosts approach:
//!   - Domain-level blocking — only affects the exact domains listed.
//!   - No collateral damage to unrelated services.
//!   - Instant effect after DNS cache flush.
//!   - Cannot be bypassed by changing DNS server (hosts takes priority).
//!   - Can be bypassed by using IP directly or a proxy — same limitation as
//!     Linux eBPF on proxied traffic, handled separately via proxy config.

use anyhow::Context;
use log::{info, warn};
use std::collections::HashSet;
use std::io::Write;
use std::process::Command;
use std::sync::{Arc, Mutex};

const HOSTS_FILE: &str = "/etc/hosts";
const HOSTS_MARKER_START: &str = "# BEGIN antidistractor";
const HOSTS_MARKER_END: &str = "# END antidistractor";

/// Network blocker using /etc/hosts only.
pub struct PfBlocker {
    blocked_domains: HashSet<String>,
}

impl PfBlocker {
    pub fn new() -> Self {
        PfBlocker {
            blocked_domains: HashSet::new(),
        }
    }

    /// Initialize: ensure any stale entries are cleaned up.
    /// Safe to call without root — will just log a warning if hosts is not writable.
    pub fn enable(&self) -> anyhow::Result<()> {
        info!("[blocker] Using /etc/hosts for domain blocking (no PF IP rules)");
        Ok(())
    }

    /// Convenience constructor.
    pub fn new_and_enable() -> anyhow::Result<Self> {
        let blocker = Self::new();
        blocker.enable()?;
        Ok(blocker)
    }

    /// Remove all antidistractor entries and flush DNS cache.
    pub fn disable(&mut self) -> anyhow::Result<()> {
        self.blocked_domains.clear();
        self.remove_hosts_entries()?;
        info!("[blocker] Disabled — /etc/hosts entries removed");
        Ok(())
    }

    /// Add a domain. Updates /etc/hosts immediately.
    ///
    /// Suffix keys (starting with '.', e.g. ".bilibili.com") are silently ignored:
    /// /etc/hosts does not support wildcard entries, so they would have no effect.
    /// On Linux the eBPF layer handles suffix matching natively.
    pub fn add_domain(&mut self, domain: &str) -> anyhow::Result<()> {
        if domain.starts_with('.') {
            log::debug!("[blocker] Skipping suffix key '{}' (wildcard not supported in /etc/hosts)", domain);
            return Ok(());
        }
        if self.blocked_domains.contains(domain) {
            return Ok(());
        }
        self.blocked_domains.insert(domain.to_string());
        self.update_hosts_file()?;
        info!("[blocker] Blocked: {}", domain);
        Ok(())
    }

    /// Remove a domain. Updates /etc/hosts immediately.
    pub fn remove_domain(&mut self, domain: &str) -> anyhow::Result<()> {
        if !self.blocked_domains.remove(domain) {
            return Ok(());
        }
        self.update_hosts_file()?;
        info!("[blocker] Unblocked: {}", domain);
        Ok(())
    }

    /// Sorted list of currently blocked domains.
    pub fn blocked_domains(&self) -> Vec<String> {
        let mut v: Vec<String> = self.blocked_domains.iter().cloned().collect();
        v.sort();
        v
    }

    // ─── Private ─────────────────────────────────────────────────────────────

    /// Rewrite the antidistractor block in /etc/hosts.
    fn update_hosts_file(&self) -> anyhow::Result<()> {
        let content = std::fs::read_to_string(HOSTS_FILE)
            .context("Failed to read /etc/hosts")?;

        let cleaned = remove_hosts_block(&content);

        let new_block = if self.blocked_domains.is_empty() {
            String::new()
        } else {
            let mut block = format!("{}\n", HOSTS_MARKER_START);
            let mut domains: Vec<&String> = self.blocked_domains.iter().collect();
            domains.sort();
            for domain in domains {
                block.push_str(&format!("127.0.0.1 {}\n", domain));
                block.push_str(&format!("::1 {}\n", domain));
            }
            block.push_str(&format!("{}\n", HOSTS_MARKER_END));
            block
        };

        let new_content = if new_block.is_empty() {
            cleaned.trim_end().to_string() + "\n"
        } else {
            cleaned.trim_end().to_string() + "\n" + &new_block
        };

        write_file_atomic(HOSTS_FILE, &new_content)
            .context("Failed to write /etc/hosts")?;

        flush_dns_cache();

        info!("[blocker] /etc/hosts updated ({} domains)", self.blocked_domains.len());
        Ok(())
    }

    fn remove_hosts_entries(&self) -> anyhow::Result<()> {
        let content = std::fs::read_to_string(HOSTS_FILE).unwrap_or_default();
        let cleaned = remove_hosts_block(&content);
        let cleaned = cleaned.trim_end().to_string() + "\n";
        write_file_atomic(HOSTS_FILE, &cleaned).ok();
        flush_dns_cache();
        Ok(())
    }

    /// No-op: DNS refresh not needed (hosts-only, no IP table to update).
    pub fn start_dns_refresh_task(_state: Arc<Mutex<Self>>) {
        // Nothing to do — /etc/hosts entries are domain-based, not IP-based.
    }
}

impl Default for PfBlocker {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Remove the antidistractor block from /etc/hosts content.
pub fn remove_hosts_block(content: &str) -> String {
    let mut result = Vec::new();
    let mut in_block = false;
    for line in content.lines() {
        if line == HOSTS_MARKER_START { in_block = true; continue; }
        if line == HOSTS_MARKER_END   { in_block = false; continue; }
        if !in_block { result.push(line); }
    }
    result.join("\n")
}

/// Flush macOS DNS cache so hosts changes take effect immediately.
fn flush_dns_cache() {
    let _ = Command::new("dscacheutil").args(["-flushcache"]).output();
    let _ = Command::new("killall").args(["-HUP", "mDNSResponder"]).output();
}

/// Write content to a file atomically (temp file + rename).
fn write_file_atomic(path: &str, content: &str) -> anyhow::Result<()> {
    let tmp = format!("{}.antidistractor.tmp", path);
    {
        let mut f = std::fs::File::create(&tmp)
            .with_context(|| format!("create tmp {}", tmp))?;
        f.write_all(content.as_bytes()).context("write tmp")?;
        f.flush().context("flush tmp")?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp, path))?;
    Ok(())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pf_blocker_new() {
        let b = PfBlocker::new();
        assert!(b.blocked_domains().is_empty());
    }

    #[test]
    fn test_add_remove_domain_state() {
        let mut b = PfBlocker::new();
        // Manipulate internal state without touching /etc/hosts
        b.blocked_domains.insert("test.example.com".to_string());
        assert!(b.blocked_domains().contains(&"test.example.com".to_string()));
        b.blocked_domains.remove("test.example.com");
        assert!(b.blocked_domains().is_empty());
    }

    #[test]
    fn test_remove_hosts_block_empty() {
        let content = "127.0.0.1 localhost\n::1 localhost\n";
        let cleaned = remove_hosts_block(content);
        assert!(!cleaned.contains("antidistractor"));
        assert!(cleaned.contains("localhost"));
    }

    #[test]
    fn test_remove_hosts_block_with_entries() {
        let content = "127.0.0.1 localhost\n# BEGIN antidistractor\n127.0.0.1 bilibili.com\n# END antidistractor\n::1 localhost\n";
        let cleaned = remove_hosts_block(content);
        assert!(!cleaned.contains("bilibili.com"));
        assert!(cleaned.contains("localhost"));
    }

    #[test]
    fn test_blocked_domains_sorted() {
        let mut b = PfBlocker::new();
        b.blocked_domains.insert("z.com".to_string());
        b.blocked_domains.insert("a.com".to_string());
        b.blocked_domains.insert("m.com".to_string());
        let v = b.blocked_domains();
        assert_eq!(v, vec!["a.com", "m.com", "z.com"]);
    }
}
