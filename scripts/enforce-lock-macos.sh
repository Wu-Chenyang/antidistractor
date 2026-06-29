#!/bin/bash
# enforce-lock-macos.sh — Forced screen lock for macOS (01:00-07:00)
#
# macOS equivalent of the Linux enforce-lock.sh + PAM mechanism.
# Run as root via launchd (com.antidistractor.screenlock.plist).
#
# Strategy:
#   1. Lock screen at 01:00 using pmset + ScreenSaverEngine
#   2. Check every 60s if screen was unlocked during the lock window
#   3. Re-lock immediately if unlocked during 01:00-07:00
#
# Note: This script is provided as a shell fallback.
# The Rust daemon (antidistractor --screen-lock-daemon) is the preferred implementation.

set -euo pipefail

LOCK_HOUR_START=1   # 01:00
LOCK_HOUR_END=7     # 07:00

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a /var/log/antidistractor-screenlock.log
}

lock_screen() {
    log "Locking screen..."

    # Method 1: pmset (puts display to sleep, triggers lock if configured)
    pmset displaysleepnow 2>/dev/null || true

    # Method 2: ScreenSaverEngine
    local saver="/System/Library/CoreServices/ScreenSaverEngine.app/Contents/MacOS/ScreenSaverEngine"
    if [ -x "$saver" ]; then
        "$saver" -background &
    fi

    log "Screen locked."
}

is_in_lock_window() {
    local hour
    hour=$(date +%H | sed 's/^0//')  # strip leading zero
    [ "$hour" -ge "$LOCK_HOUR_START" ] && [ "$hour" -lt "$LOCK_HOUR_END" ]
}

is_screen_locked() {
    # Check CGSession for lock state
    CGSession -currentDictionary 2>/dev/null | grep -A1 kCGSSessionScreenIsLocked | grep -q "1"
}

log "Antidistractor screen lock daemon started (lock window: ${LOCK_HOUR_START}:00-${LOCK_HOUR_END}:00)"

last_locked_hour=""

while true; do
    sleep 60

    current_hour=$(date +%H | sed 's/^0//')

    if is_in_lock_window; then
        if [ "$current_hour" != "$last_locked_hour" ] || ! is_screen_locked; then
            lock_screen
            last_locked_hour="$current_hour"
        fi
    else
        last_locked_hour=""
    fi
done
