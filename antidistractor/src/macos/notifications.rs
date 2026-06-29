//! macOS desktop notifications.
//!
//! Replaces Linux's notify-send. Uses osascript to deliver macOS
//! UserNotifications without requiring entitlements or App Store distribution.

use log::warn;
use std::process::Command;

/// Send a generic notification.
pub fn send_notification(title: &str, message: &str) {
    let script = format!(
        "display notification \"{}\" with title \"{}\"",
        escape_applescript(message),
        escape_applescript(title)
    );

    let result = Command::new("osascript")
        .args(["-e", &script])
        .output();

    if let Err(e) = result {
        warn!("[notifications] Failed to send notification: {}", e);
    }
}

/// Send a notification that an app was blocked.
pub fn send_app_blocked_notification(app_name: &str) {
    send_notification(
        "Antidistractor",
        &format!("已阻止 \"{}\" 启动", app_name),
    );
}

/// Send a notification that a domain was blocked.
#[allow(dead_code)]
pub fn send_domain_blocked_notification(domain: &str) {
    send_notification(
        "Antidistractor",
        &format!("已封锁域名: {}", domain),
    );
}

/// Send a screen lock notification.
#[allow(dead_code)]
pub fn send_screen_lock_notification() {
    send_notification(
        "Antidistractor - 强制锁屏",
        "当前为休息时段 (01:00-07:00)，屏幕已锁定",
    );
}

/// Escape special characters in AppleScript strings.
/// AppleScript strings use double quotes; backslash and quote need escaping.
fn escape_applescript(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_applescript() {
        assert_eq!(escape_applescript("hello"), "hello");
        assert_eq!(escape_applescript("say \"hi\""), r#"say \"hi\""#);
        assert_eq!(escape_applescript("back\\slash"), r#"back\\slash"#);
    }

    #[test]
    fn test_escape_with_chinese() {
        // Chinese characters should pass through unchanged
        let s = "已阻止 WeChat 启动";
        assert_eq!(escape_applescript(s), s);
    }
}
