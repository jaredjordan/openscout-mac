// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "OpenScout",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "OpenScoutCore", targets: ["OpenScoutCore"]),
        .library(name: "OpenScoutMac", targets: ["OpenScoutMac"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        // Platform-neutral logic. Builds and tests on macOS and Linux.
        .target(
            name: "OpenScoutCore",
            dependencies: [.product(name: "Crypto", package: "swift-crypto")],
            path: "Sources/OpenScoutCore"
        ),
        // macOS-only glue: file system events, login items, notifications.
        .target(
            name: "OpenScoutMac",
            dependencies: ["OpenScoutCore"],
            path: "Sources/OpenScoutMac"
        ),
        .testTarget(
            name: "OpenScoutCoreTests",
            dependencies: ["OpenScoutCore"],
            path: "tests/OpenScoutCoreTests",
            resources: [.copy("Fixtures")]
        ),
    ]
)
