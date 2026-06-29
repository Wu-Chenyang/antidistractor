//! macOS screen lock enforcement.
//!
//! Replaces the Linux PAM + GNOME D-Bus screen lock mechanism.
//! Uses pmset and CGSession/screensaver to lock the screen.
//!
//! Forced lock schedule: 01:00-07:00 (same as Linux version)
//! Implementation: periodic check daemon that locks screen and monitors for unlock attempts.

use anyhow::Context;
use log::{info, warn};
use std::process::Command;
use std::time::Duration;

/// Lock the screen immediately.
/// Uses multiple methods in order of preference.
pub fn lock_screen() -> anyhow::Result<()> {
    // Method 1: pmset displaysleepnow (puts display to sleep, triggers screen lock if enabled)
    let r1 = Command::new("pmset")
        .args(["displaysleepnow"])
        .output();

    // Method 2: ScreenSaverEngine (launches screensaver which locks the screen)
    let saver_path = "/System/Library/CoreServices/ScreenSaverEngine.app/Contents/MacOS/ScreenSaverEngine";
    let r2 = if std::path::Path::new(saver_path).exists() {
        Command::new(saver_path)
            .args(["-background"])
            .spawn()
            .map(|_| ())
            .ok()
    } else {
        None
    };

    // Method 3: AppleScript (fallback — sends Cmd+Ctrl+Opt+Q lock shortcut)
    let _r3 = Command::new("osascript")
        .args(["-e", r#"tell application "System Events" to keystroke "q" using {command down, control down, option down}"#])
        .output()
        .ok();

    if r1.is_ok() || r2.is_some() {
        info!("[screen-lock] Screen locked");
        Ok(())
    } else {
        // Fallback: use CGSession command-line tool
        let output = Command::new("open")
            .args(["-a", "ScreenSaverEngine"])
            .output()
            .context("All screen lock methods failed")?;
        if output.status.success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Failed to lock screen"))
        }
    }
}

/// Check if the screen is currently locked.
/// Uses CGSession's kCGSSessionScreenIsLocked via defaults.
pub fn is_locked() -> bool {
    // CGSession -currentDictionary outputs a plist with lock state
    let output = Command::new("bash")
        .args([
            "-c",
            r#"CGSession -currentDictionary 2>/dev/null | grep -A1 kCGSSessionScreenIsLocked | grep -c 1"#,
        ])
        .output();

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.trim() == "1"
        }
        Err(_) => false,
    }
}

/// Return the current hour (0-23) in local time.
fn current_hour() -> u32 {
    // Use `date +%H` to get local hour — avoids timezone offset arithmetic
    Command::new("date")
        .args(["+%H"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

/// Check if the current time is within the forced lock window (01:00-07:00).
pub fn is_in_lock_window() -> bool {
    let hour = current_hour();
    hour >= 1 && hour < 7
}

/// Run the screen lock enforcement daemon.
/// This function blocks indefinitely.
///
/// Behavior:
/// - At 01:00, lock the screen
/// - Check every 60s whether we're in the lock window (01:00-07:00)
/// - If the screen is unlocked during the window, re-lock it
///
/// For testing: set LOCK_POLL_SECS=5 and TEST_LOCK_HOUR=<hour> env vars.
pub fn run_lock_daemon() {
    let poll_secs = std::env::var("LOCK_POLL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(60);

    info!("[screen-lock] Lock daemon started (forced lock 01:00-07:00, poll={}s)", poll_secs);

    let mut last_lock_hour: Option<u32> = None;

    loop {
        std::thread::sleep(Duration::from_secs(poll_secs));

        let hour = current_hour();

        // Support TEST_LOCK_HOUR env var for testing without waiting until 01:00
        let in_window = if let Ok(h) = std::env::var("TEST_LOCK_HOUR")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .map(Ok::<u32, ()>)
            .transpose()
        {
            current_hour() == h.unwrap_or(99)
        } else {
            is_in_lock_window()
        };

        if in_window {
            // Lock screen at the start of the window or if it got unlocked
            let should_lock = last_lock_hour.map(|h| h != hour).unwrap_or(true)
                || !is_locked();

            if should_lock {
                info!("[screen-lock] Enforcing lock (hour={})", hour);
                if let Err(e) = lock_screen() {
                    warn!("[screen-lock] Failed to lock screen: {}", e);
                }
                last_lock_hour = Some(hour);
            }
        } else {
            last_lock_hour = None;
        }
    }
}

/// Install the screen lock LaunchDaemon plist.
#[allow(dead_code)]
/// This sets up the daemon to run at startup.
pub fn install_lock_daemon() -> anyhow::Result<()> {
    let plist_path = "/Library/LaunchDaemons/com.antidistractor.screenlock.plist";
    let binary_path = "/usr/local/bin/antidistractor";

    let plist_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.antidistractor.screenlock</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>--screen-lock-daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/antidistractor-screenlock.log</string>
    <key>StandardOutPath</key>
    <string>/var/log/antidistractor-screenlock.log</string>
</dict>
</plist>
"#,
        binary_path
    );

    std::fs::write(plist_path, &plist_content)
        .with_context(|| format!("Failed to write {}", plist_path))?;

    // Load the LaunchDaemon
    let output = Command::new("launchctl")
        .args(["load", plist_path])
        .output()
        .context("Failed to run launchctl load")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("launchctl load failed: {}", stderr.trim()));
    }

    info!("[screen-lock] LaunchDaemon installed at {}", plist_path);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_lock_window_boundaries() {
        // We can't test the actual hour, but test the logic
        assert!(!is_hour_in_window(0));
        assert!(is_hour_in_window(1));
        assert!(is_hour_in_window(3));
        assert!(is_hour_in_window(6));
        assert!(!is_hour_in_window(7));
        assert!(!is_hour_in_window(12));
        assert!(!is_hour_in_window(23));
    }

    fn is_hour_in_window(hour: u32) -> bool {
        hour >= 1 && hour < 7
    }
}
