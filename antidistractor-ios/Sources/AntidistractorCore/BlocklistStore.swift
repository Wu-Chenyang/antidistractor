/// BlocklistStore.swift
/// Persistent storage for the current blocklist.
/// Saved to App Group container so the DeviceActivityMonitor Extension can read it.

import Foundation

/// The blocklist that antidistractor enforces.
public struct Blocklist: Codable, Sendable {
    /// App bundle IDs to block, e.g. ["com.bilibili.app.iphone", "com.ss.iphone.ugc.Aweme"]
    public var bundleIDs: Set<String>

    /// Website domains to block in Safari and WebViews, e.g. ["bilibili.com", "tiktok.com"]
    public var domains: Set<String>

    /// App Store category IDs to block.
    /// Common values: entertainment=6016, socialNetworking=6005, games=6014
    public var categoryIDs: Set<Int>

    public init(bundleIDs: Set<String> = [],
                domains: Set<String> = [],
                categoryIDs: Set<Int> = []) {
        self.bundleIDs = bundleIDs
        self.domains = domains
        self.categoryIDs = categoryIDs
    }

    public var isEmpty: Bool {
        bundleIDs.isEmpty && domains.isEmpty && categoryIDs.isEmpty
    }
}

/// Persists the blocklist to the App Group container shared between
/// the main app and the DeviceActivityMonitor Extension.
public final class BlocklistStore: @unchecked Sendable {

    // MARK: - Singleton

    public static let shared = BlocklistStore()

    // MARK: - App Group

    /// Must match the App Group identifier in both targets' entitlements.
    /// Change this to your actual App Group ID before shipping.
    public static let appGroupID = "group.com.antidistractor.shared"

    private let defaults: UserDefaults

    private init() {
        // Fall back to standard defaults if App Group is not configured
        // (e.g. during unit tests or before entitlements are set up)
        self.defaults = UserDefaults(suiteName: Self.appGroupID)
                     ?? UserDefaults.standard
    }

    // MARK: - Keys

    private enum Key {
        static let blocklist = "antidistractor.blocklist"
        static let blockingEnabled = "antidistractor.blockingEnabled"
    }

    // MARK: - Public API

    /// Load the current blocklist from shared storage.
    public func load() -> Blocklist {
        guard let data = defaults.data(forKey: Key.blocklist),
              let list = try? JSONDecoder().decode(Blocklist.self, from: data)
        else {
            return Blocklist()
        }
        return list
    }

    /// Persist a blocklist to shared storage.
    public func save(_ blocklist: Blocklist) {
        guard let data = try? JSONEncoder().encode(blocklist) else { return }
        defaults.set(data, forKey: Key.blocklist)
    }

    /// Whether blocking is currently active.
    public var blockingEnabled: Bool {
        get { defaults.bool(forKey: Key.blockingEnabled) }
        set { defaults.set(newValue, forKey: Key.blockingEnabled) }
    }
}
