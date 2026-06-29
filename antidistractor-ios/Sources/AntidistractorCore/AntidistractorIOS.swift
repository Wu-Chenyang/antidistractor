/// AntidistractorIOS.swift
/// Public entry point — import this file to use the library.
/// Provides a unified setup call for the host app.

import Foundation
import FamilyControls

/// Top-level namespace for antidistractor iOS.
public enum AntidistractorIOS {

    /// Call this once at app launch (e.g. in App.init or AppDelegate.didFinishLaunching).
    /// Sets up the shared secret for the HTTP control server and checks auth status.
    ///
    /// - Parameter sharedSecret: A random string shared with the host multi-platform app.
    ///   Generate once and store in Keychain. Pass the same value to the macOS daemon.
    ///   If empty, the HTTP server accepts all requests (only safe on localhost).
    @MainActor
    public static func setup(sharedSecret: String = "") {
        // Check existing authorization
        BlockingManager.shared.checkAuthorizationStatus()

        // Re-apply blocklist if blocking was active before app restart
        if BlocklistStore.shared.blockingEnabled {
            let list = BlocklistStore.shared.load()
            if !list.isEmpty {
                BlockingManager.shared.applyBlocklist(list)
            }
        }

        // Configure HTTP server secret
        AntidistractorIOS.controlServerSecret = sharedSecret
    }

    /// The shared secret for the HTTP control server.
    /// Set by setup(), read by ControlServer.
    public static var controlServerSecret: String = ""

    /// Convenience: the default HTTP port.
    public static let defaultPort: UInt16 = 18964
}
