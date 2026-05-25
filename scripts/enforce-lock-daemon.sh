#!/bin/bash
# enforce-lock-daemon.sh
# Monitors time and forces screen lock during 01:00-07:00
# Also watches D-Bus for any unlock attempts and re-locks immediately

LOCK_START=1
LOCK_END=7

is_locked_hour() {
    local hour=$(date +%H)
    hour=$((10#$hour))
    [ "$hour" -ge "$LOCK_START" ] && [ "$hour" -lt "$LOCK_END" ]
}

lock_all_sessions() {
    loginctl list-sessions --no-legend | while read -r sid rest; do
        loginctl lock-session "$sid" 2>/dev/null
    done
}

# Main loop
while true; do
    if is_locked_hour; then
        lock_all_sessions

        # Monitor D-Bus for unlock events, timeout after 55s to re-check hour
        timeout 55 dbus-monitor --system \
            "type='signal',interface='org.freedesktop.login1.Session',member='Lock'" \
            "type='signal',interface='org.gnome.ScreenSaver',member='ActiveChanged'" \
            2>/dev/null | while read -r line; do
            if echo "$line" | grep -q "boolean false\|ActiveChanged"; then
                sleep 0.5
                lock_all_sessions
            fi
        done
    else
        sleep 30
    fi
done
