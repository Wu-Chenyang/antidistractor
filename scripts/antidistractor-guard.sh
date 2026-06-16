#!/bin/bash
# antidistractor-guard.sh — Multi-layer anti-bypass guardian (v2)
# Runs as root via systemd. Monitors and auto-repairs blocking layers.
#
# IMPORTANT: Does NOT use chattr +i on override.yaml (breaks Mihomo Party).
# Only monitors content and repairs when tampered.

set -euo pipefail

HOSTS_FILE="/etc/hosts"
HOSTS_MARKER="# === Antidistractor: bilibili block ==="

OVERRIDE_REGISTRY="/home/wucy/.config/mihomo-party/override.yaml"
OVERRIDE_FILE="/home/wucy/.config/mihomo-party/override/19e5f6e3177.yaml"

POLL_INTERVAL=10

# --- Expected hosts content ---
HOSTS_BLOCK='# === Antidistractor: bilibili block ===
0.0.0.0 bilibili.com
0.0.0.0 www.bilibili.com
0.0.0.0 m.bilibili.com
0.0.0.0 api.bilibili.com
0.0.0.0 api.vc.bilibili.com
0.0.0.0 app.bilibili.com
0.0.0.0 live.bilibili.com
0.0.0.0 t.bilibili.com
0.0.0.0 space.bilibili.com
0.0.0.0 search.bilibili.com
0.0.0.0 member.bilibili.com
0.0.0.0 passport.bilibili.com
0.0.0.0 account.bilibili.com
0.0.0.0 manga.bilibili.com
0.0.0.0 hdslb.com
0.0.0.0 www.hdslb.com
0.0.0.0 i0.hdslb.com
0.0.0.0 i1.hdslb.com
0.0.0.0 i2.hdslb.com
0.0.0.0 s1.hdslb.com
0.0.0.0 bilivideo.com
0.0.0.0 bilivideo.cn
0.0.0.0 biliapi.net
0.0.0.0 biliapi.com
0.0.0.0 zuoleme.com
0.0.0.0 www.zuoleme.com
0.0.0.0 gpgjqw.com
0.0.0.0 www.gpgjqw.com
0.0.0.0 igq.gpgjqw.com
# === End Antidistractor ==='

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [guard] $*"
}

# --- Check & repair functions ---

check_hosts() {
    if ! grep -q "$HOSTS_MARKER" "$HOSTS_FILE" 2>/dev/null; then
        log "REPAIR: /etc/hosts missing bilibili block, restoring..."
        # Remove any partial antidistractor blocks
        sed -i '/# === Antidistractor: bilibili block ===/,/# === End Antidistractor ===/d' "$HOSTS_FILE" 2>/dev/null || true
        printf '\n%s\n' "$HOSTS_BLOCK" >> "$HOSTS_FILE"
        log "REPAIR: /etc/hosts restored"
    fi
}

check_override_registry() {
    # Ensure the 19e5f6e3177 entry exists and is global: true in override.yaml
    # We do NOT overwrite the file — only patch the specific entry if needed.
    # Mihomo Party may update 'updated' timestamps; we must not fight that.

    if [ ! -f "$OVERRIDE_REGISTRY" ]; then
        return
    fi

    if grep -q "id: 19e5f6e3177" "$OVERRIDE_REGISTRY" 2>/dev/null; then
        # Entry exists. Check if global is true.
        # Use awk: find "19e5f6e3177", then find the next "global:" within that block.
        local is_global
        is_global=$(awk '/19e5f6e3177/{found=1} found && /global:/{print $2; exit}' "$OVERRIDE_REGISTRY")

        if [ "$is_global" != "true" ]; then
            log "REPAIR: override registry has global!=true, fixing..."
            # Robust replacement: find our id, then replace the next "global:" line
            awk '
                /19e5f6e3177/ { found=1 }
                found && /global:/ { sub(/global:.*/, "global: true"); found=0 }
                { print }
            ' "$OVERRIDE_REGISTRY" > "${OVERRIDE_REGISTRY}.tmp" && \
                mv "${OVERRIDE_REGISTRY}.tmp" "$OVERRIDE_REGISTRY" && \
                chown wucy:wucy "$OVERRIDE_REGISTRY"
            log "REPAIR: override registry fixed"
        fi
    else
        # Entry was deleted entirely. Re-add it.
        log "REPAIR: override registry missing 19e5f6e3177 entry, restoring..."
        sed -i '/^items:/a\  - id: 19e5f6e3177\n    name: 新建 YAML\n    type: local\n    ext: yaml\n    global: true\n    updated: 1779717517687' "$OVERRIDE_REGISTRY" 2>/dev/null || true
        chown wucy:wucy "$OVERRIDE_REGISTRY"
        log "REPAIR: override registry entry restored"
    fi
}

check_override_file() {
    # Ensure the override YAML file exists.
    # This file SHOULD be chattr +i, so if it's missing, something serious happened.
    # Restore from the backup kept in the project repo.
    local BACKUP="/home/wucy/Workspace/antidistractor/scripts/override-backup.yaml"
    if [ ! -f "$OVERRIDE_FILE" ] && [ -f "$BACKUP" ]; then
        log "REPAIR: override file missing, restoring from backup..."
        cp "$BACKUP" "$OVERRIDE_FILE"
        chown wucy:wucy "$OVERRIDE_FILE"
        chattr +i "$OVERRIDE_FILE" 2>/dev/null || true
        log "REPAIR: override file restored and locked"
    fi
}

check_ebpf_service() {
    if ! systemctl is-active --quiet antidistractor.service; then
        log "REPAIR: antidistractor.service not running, restarting..."
        systemctl restart antidistractor.service 2>/dev/null || true
        log "REPAIR: antidistractor.service restarted"
    fi
}

# --- Main loop ---

log "=== Antidistractor Guard v2 Started ==="

while true; do
    check_hosts
    check_override_registry
    check_override_file
    check_ebpf_service
    sleep "$POLL_INTERVAL"
done
