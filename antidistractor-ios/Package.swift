// swift-tools-version: 5.9
// Antidistractor iOS — Swift Package
//
// Provides screen-time-based blocking for iOS via ManagedSettings + FamilyControls.
// Exposes a local HTTP server so the host app can call blocking functions
// over a simple REST API (same interface pattern as the macOS Unix socket control server).
//
// Required entitlements (must be added to the host app's .entitlements file):
//   com.apple.developer.family-controls
//
// Required Info.plist keys in the host app:
//   NSFamilyControlsUsageDescription — explain why you need Screen Time access

import PackageDescription

let package = Package(
    name: "AntidistractorIOS",
    platforms: [
        .iOS(.v16)   // ManagedSettings / FamilyControls require iOS 16+
    ],
    products: [
        // Core library — import this in the host app
        .library(name: "AntidistractorCore", targets: ["AntidistractorCore"]),
        // Embedded HTTP server — import alongside Core
        .library(name: "AntidistractorServer", targets: ["AntidistractorServer"]),
    ],
    dependencies: [],
    targets: [
        // ── Core: FamilyControls + ManagedSettings wrapper ──────────────────
        .target(
            name: "AntidistractorCore",
            dependencies: [],
            path: "Sources/AntidistractorCore",
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ]
        ),
        // ── Server: local HTTP control server ────────────────────────────────
        .target(
            name: "AntidistractorServer",
            dependencies: ["AntidistractorCore"],
            path: "Sources/AntidistractorServer"
        ),
        // ── Tests ─────────────────────────────────────────────────────────────
        .testTarget(
            name: "AntidistractorCoreTests",
            dependencies: ["AntidistractorCore"],
            path: "Tests/AntidistractorCoreTests"
        ),
    ]
)
