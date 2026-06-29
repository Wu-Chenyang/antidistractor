/// DeviceActivityMonitorExtension.swift
/// DeviceActivityMonitor Extension — runs in background to apply/remove blocking
/// at scheduled times (e.g. 01:00-07:00 forced lock window).
///
/// This Extension is a separate target in Xcode. It shares the App Group
/// container with the main app to read the blocklist and enabled state.
///
/// To register a schedule from the main app:
///   DeviceActivityCenter().startMonitoring(.lockWindow,
///       during: DateInterval(...),
///       events: [:])
///
/// The extension's intervalDidStart/intervalDidEnd callbacks then apply/clear
/// the ManagedSettingsStore restrictions.

import DeviceActivity
import ManagedSettings
import Foundation

// MARK: - Activity names

extension DeviceActivityName {
    /// The nightly forced lock window (01:00-07:00).
    static let lockWindow = DeviceActivityName("antidistractor.lockWindow")
    /// A user-initiated focus session.
    static let focusSession = DeviceActivityName("antidistractor.focusSession")
}

// MARK: - Monitor

class AntidistractorMonitor: DeviceActivityMonitor {

    private let store = ManagedSettingsStore()

    // Called when a monitored interval starts (e.g. 01:00 — lock window begins)
    override func intervalDidStart(for activity: DeviceActivityName) {
        super.intervalDidStart(for: activity)
        applyCurrentBlocklist()
    }

    // Called when a monitored interval ends (e.g. 07:00 — lock window ends)
    override func intervalDidEnd(for activity: DeviceActivityName) {
        super.intervalDidEnd(for: activity)

        switch activity {
        case .lockWindow:
            // Remove restrictions when the forced window ends
            store.clearAllSettings()
        case .focusSession:
            // Focus session ended — clear
            store.clearAllSettings()
        default:
            break
        }
    }

    // Called when a monitored event threshold is reached (unused for now)
    override func eventDidReachThreshold(_ event: DeviceActivityEvent.Name,
                                         activity: DeviceActivityName) {
        super.eventDidReachThreshold(event, activity: activity)
    }

    // MARK: - Apply blocklist

    /// Read the blocklist from the shared App Group container and apply it.
    /// This runs in the Extension process — no access to the main app's memory.
    private func applyCurrentBlocklist() {
        let defaults = UserDefaults(suiteName: "group.com.antidistractor.shared")
                    ?? UserDefaults.standard

        guard defaults.bool(forKey: "antidistractor.blockingEnabled"),
              let data = defaults.data(forKey: "antidistractor.blocklist"),
              let blocklist = try? JSONDecoder().decode(StoredBlocklist.self, from: data)
        else {
            // Blocking disabled or no blocklist — clear
            store.clearAllSettings()
            return
        }

        // Apply website blocking
        if !blocklist.domains.isEmpty {
            store.webContent.blockedByFilter = .specific(
                WebContentSettings.FilterPolicy(
                    exceptedWebDomains: [],
                    blockedWebDomains: Set(blocklist.domains.map { WebDomain(domain: $0) })
                )
            )
        }

        // App blocking requires tokens stored by the main app.
        // The Extension reads the serialized FamilyActivitySelection from shared defaults.
        if let selectionData = defaults.data(forKey: "antidistractor.appSelection"),
           let selection = try? JSONDecoder().decode(FamilyActivitySelection.self, from: selectionData) {
            if !selection.applicationTokens.isEmpty {
                store.application.blockedApplications = selection.applicationTokens
            }
            if !selection.categoryTokens.isEmpty {
                store.application.blockedApplicationCategories = selection.categoryTokens
            }
        }
    }
}

// MARK: - Minimal Codable blocklist (no dependency on AntidistractorCore)

/// Duplicated here because Extensions cannot import the main app's modules.
private struct StoredBlocklist: Codable {
    var bundleIDs: Set<String>
    var domains: Set<String>
    var categoryIDs: Set<Int>
}
