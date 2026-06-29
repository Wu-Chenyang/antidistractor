/// BlockingManager.swift
/// Core blocking engine — wraps FamilyControls + ManagedSettings.
///
/// FamilyControls provides the authorization gate.
/// ManagedSettings applies the actual restrictions.
///
/// NOTE: These APIs require the com.apple.developer.family-controls entitlement
/// and only work on real devices (not the Simulator).

import Foundation
import FamilyControls
import ManagedSettings
import DeviceActivity

/// Main actor so all UI-touching calls happen on the main thread.
@MainActor
public final class BlockingManager: ObservableObject {

    // MARK: - Published state

    @Published public private(set) var isAuthorized = false
    @Published public private(set) var isBlocking = false
    @Published public private(set) var lastError: String?

    // MARK: - Dependencies

    private let store = ManagedSettingsStore()
    private let authCenter = AuthorizationCenter.shared
    private let blocklistStore = BlocklistStore.shared

    // MARK: - Singleton

    public static let shared = BlockingManager()
    private init() {
        // Reflect persisted state on launch
        isBlocking = blocklistStore.blockingEnabled
    }

    // MARK: - Authorization

    /// Request FamilyControls authorization from the user.
    /// Must be called before any blocking operations.
    /// Shows a system prompt — call this from a user-initiated action (button tap).
    public func requestAuthorization() async {
        do {
            try await authCenter.requestAuthorization(for: .individual)
            isAuthorized = true
            lastError = nil
        } catch {
            isAuthorized = false
            lastError = "授权失败: \(error.localizedDescription)"
        }
    }

    /// Check current authorization status without prompting.
    public func checkAuthorizationStatus() {
        isAuthorized = (authCenter.authorizationStatus == .approved)
    }

    // MARK: - Blocking control

    /// Apply the given blocklist immediately.
    /// Replaces any previously applied restrictions.
    public func applyBlocklist(_ blocklist: Blocklist) {
        guard isAuthorized else {
            lastError = "未授权，请先调用 requestAuthorization()"
            return
        }

        // ── App blocking ──────────────────────────────────────────────────
        if blocklist.bundleIDs.isEmpty {
            store.application.blockedApplications = nil
        } else {
            // Convert bundle ID strings to ApplicationTokens via FamilyActivityPicker
            // ApplicationToken is opaque and must be obtained through the picker UI.
            // We store tokens in BlocklistStore after the user selects apps.
            // For HTTP-API-driven blocking, we use the token cache below.
            let tokens = tokenCache.tokens(for: blocklist.bundleIDs)
            store.application.blockedApplications = tokens.isEmpty ? nil : tokens
        }

        // ── Category blocking ─────────────────────────────────────────────
        if blocklist.categoryIDs.isEmpty {
            store.application.blockedApplicationCategories = nil
        } else {
            let categories = ActivityCategoryToken.categories(for: blocklist.categoryIDs)
            store.application.blockedApplicationCategories = categories.isEmpty ? nil : categories
        }

        // ── Website blocking ──────────────────────────────────────────────
        if blocklist.domains.isEmpty {
            store.webContent.blockedByFilter = nil
        } else {
            store.webContent.blockedByFilter = .specific(
                WebContentSettings.FilterPolicy(
                    exceptedWebDomains: [],
                    blockedWebDomains: Set(blocklist.domains.map {
                        WebDomain(domain: $0)
                    })
                )
            )
        }

        // ── Persist state ─────────────────────────────────────────────────
        blocklistStore.save(blocklist)
        blocklistStore.blockingEnabled = true
        isBlocking = true
        lastError = nil
    }

    /// Remove all restrictions immediately.
    public func clearBlocklist() {
        store.clearAllSettings()
        blocklistStore.save(Blocklist())
        blocklistStore.blockingEnabled = false
        isBlocking = false
        lastError = nil
    }

    /// Add domains to the current blocklist without replacing other entries.
    public func addDomains(_ domains: [String]) {
        var current = blocklistStore.load()
        current.domains.formUnion(domains)
        applyBlocklist(current)
    }

    /// Remove domains from the current blocklist.
    public func removeDomains(_ domains: [String]) {
        var current = blocklistStore.load()
        current.domains.subtract(domains)
        applyBlocklist(current)
    }

    /// Add app bundle IDs to the current blocklist.
    /// Note: bundle IDs are stored but actual blocking requires ApplicationTokens
    /// obtained via FamilyActivityPicker. See AppPickerView.
    public func addBundleIDs(_ ids: [String]) {
        var current = blocklistStore.load()
        current.bundleIDs.formUnion(ids)
        blocklistStore.save(current)
        // Re-apply to pick up any newly cached tokens
        applyBlocklist(current)
    }

    /// Remove app bundle IDs from the current blocklist.
    public func removeBundleIDs(_ ids: [String]) {
        var current = blocklistStore.load()
        current.bundleIDs.subtract(ids)
        applyBlocklist(current)
    }

    /// Add App Store category IDs to the current blocklist.
    public func addCategories(_ ids: [Int]) {
        var current = blocklistStore.load()
        current.categoryIDs.formUnion(ids)
        applyBlocklist(current)
    }

    // MARK: - Token cache (for app blocking)

    private let tokenCache = AppTokenCache.shared
}

// MARK: - AppTokenCache

/// Maps bundle ID strings ↔ ApplicationTokens.
/// Tokens are opaque values obtained via FamilyActivityPicker;
/// they cannot be constructed from bundle IDs directly.
/// The cache is populated when the user selects apps via the picker UI.
public final class AppTokenCache: @unchecked Sendable {

    public static let shared = AppTokenCache()

    private var cache: [String: ApplicationToken] = [:]
    private let lock = NSLock()

    /// Store tokens obtained from FamilyActivityPicker.
    public func store(tokens: Set<ApplicationToken>, for bundleIDs: [String]) {
        lock.withLock {
            // Map positionally — caller must ensure order matches
            zip(bundleIDs, tokens).forEach { id, token in
                cache[id] = token
            }
        }
    }

    /// Store a FamilyActivitySelection (from the picker) directly.
    /// Extracts all application tokens and associates them with the selection.
    public func store(selection: FamilyActivitySelection) {
        lock.withLock {
            // Tokens from selection — we store them keyed by their description
            // since we can't extract bundle IDs from tokens directly
            for token in selection.applicationTokens {
                let key = token.hashValue.description
                cache[key] = token
            }
        }
    }

    /// Retrieve tokens for the given bundle IDs (returns only cached ones).
    public func tokens(for bundleIDs: Set<String>) -> Set<ApplicationToken> {
        lock.withLock {
            Set(bundleIDs.compactMap { cache[$0] })
        }
    }

    /// All cached tokens (used when applying a full selection).
    public func allTokens() -> Set<ApplicationToken> {
        lock.withLock { Set(cache.values) }
    }
}

// MARK: - ActivityCategoryToken helper

extension ActivityCategoryToken {
    /// Convert numeric category IDs to ActivityCategoryTokens.
    /// Category tokens are also opaque — this uses a workaround via
    /// FamilyActivitySelection's categoryTokens.
    /// In practice, categories are best selected via FamilyActivityPicker.
    static func categories(for ids: Set<Int>) -> Set<ActivityCategoryToken> {
        // ActivityCategoryToken cannot be constructed from an Int directly.
        // Return empty — categories must be selected via FamilyActivityPicker.
        // TODO: populate via picker selection cache (same pattern as AppTokenCache)
        return []
    }
}
