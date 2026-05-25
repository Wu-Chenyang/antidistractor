#!/bin/bash
# Antidistractor: Enforce screen lock during 01:00-06:59
# Used by PAM to deny authentication during blocked hours
HOUR=$(date +%H)
if [ "$HOUR" -ge 1 ] && [ "$HOUR" -lt 7 ]; then
    exit 1
fi
exit 0
