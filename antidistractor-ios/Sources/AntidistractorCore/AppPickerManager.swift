/// AppPickerManager.swift
/// Manages FamilyActivityPicker selection — the only way to get ApplicationTokens.
///
/// ApplicationToken is opaque: you cannot construct one from a bundle ID string.
/// The user must select apps via the system-provided FamilyActivityPicker sheet.
/// Once selected, the tokens are cached and used by BlockingManager.

import Foundation
import FamilyControls
import ManagedSettings

/// Holds the current FamilyActivitySelection (apps + categories chosen by user).
@MainActor
public final class AppPickerManager: ObservableObject {

    public static let shared = AppPickerManager()

    /// The current selection from FamilyActivityPicker.
    /// Bind this to FamilyActivityPicker in SwiftUI.
    @Published public var selection = FamilyActivitySelection()

    /// Whether the picker sheet is showing.
    @Published public var isPickerPresented = false

    private init() {
        loadPersistedSelection()
    }

    // MARK: - Persistence

    private let defaults = UserDefaults(suiteName: BlocklistStore.appGroupID)
                        ?? UserDefaults.standard
    private let selectionKey = "antidistractor.appSelection"

    private func loadPersistedSelection() {
        guard let data = defaults.data(forKey: selectionKey),
              let saved = try? JSONDecoder().decode(FamilyActivitySelection.self, from: data)
        else { return }
        selection = saved
        AppTokenCache.shared.store(selection: saved)
    }

    /// Call after the user confirms the picker selection.
    public func applySelection(_ newSelection: FamilyActivitySelection) {
        selection = newSelection
        // Cache the tokens
        AppTokenCache.shared.store(selection: newSelection)
        // Persist
        if let data = try? JSONEncoder().encode(newSelection) {
            defaults.set(data, forKey: selectionKey)
        }
        // Re-apply current blocklist so new app tokens take effect
        let current = BlocklistStore.shared.load()
        Task { @MainActor in
            BlockingManager.shared.applyBlocklist(current)
        }
    }

    /// Number of apps currently selected.
    public var selectedAppCount: Int {
        selection.applicationTokens.count
    }

    /// Number of categories currently selected.
    public var selectedCategoryCount: Int {
        selection.categoryTokens.count
    }
}
