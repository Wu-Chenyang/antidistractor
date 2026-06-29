/// ScheduleManager.swift
/// Manages DeviceActivity schedules for timed blocking windows.
/// Corresponds to the Linux/macOS enforce-lock (01:00-07:00) feature.

import Foundation
import DeviceActivity

@MainActor
public final class ScheduleManager: ObservableObject {

    public static let shared = ScheduleManager()
    private let center = DeviceActivityCenter()
    private init() {}

    // MARK: - Forced lock window (01:00-07:00)

    /// Start the nightly forced lock schedule.
    /// The DeviceActivityMonitor Extension will apply/remove restrictions automatically.
    public func startNightlyLock(startHour: Int = 1, endHour: Int = 7) throws {
        let schedule = DeviceActivitySchedule(
            intervalStart: DateComponents(hour: startHour, minute: 0),
            intervalEnd: DateComponents(hour: endHour, minute: 0),
            repeats: true
        )
        try center.startMonitoring(.lockWindow, during: schedule)
    }

    /// Stop the nightly forced lock schedule.
    public func stopNightlyLock() {
        center.stopMonitoring([.lockWindow])
    }

    // MARK: - Focus session (manual, time-limited)

    /// Start a focus session lasting `minutes` minutes.
    public func startFocusSession(minutes: Int) throws {
        let now = Date()
        let end = Calendar.current.date(byAdding: .minute, value: minutes, to: now) ?? now

        let startComponents = Calendar.current.dateComponents([.hour, .minute], from: now)
        let endComponents = Calendar.current.dateComponents([.hour, .minute], from: end)

        let schedule = DeviceActivitySchedule(
            intervalStart: startComponents,
            intervalEnd: endComponents,
            repeats: false
        )
        try center.startMonitoring(.focusSession, during: schedule)
    }

    /// Stop any active focus session.
    public func stopFocusSession() {
        center.stopMonitoring([.focusSession])
    }

    // MARK: - Status

    /// Whether the nightly lock schedule is active.
    public var isNightlyLockActive: Bool {
        // DeviceActivityCenter has no direct "isMonitoring" API.
        // Track state in UserDefaults.
        UserDefaults(suiteName: BlocklistStore.appGroupID)?
            .bool(forKey: "antidistractor.nightlyLockActive") ?? false
    }
}
