// swift-tools-version:5.9
import PackageDescription

// PortaKit wraps the Rust tunnel (Porta.xcframework, built by
// scripts/build-apple.sh) for the macOS and iOS apps and their packet tunnel
// extension.
let package = Package(
    name: "PortaKit",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "PortaKit", targets: ["PortaKit"]),
    ],
    targets: [
        .binaryTarget(name: "CPorta", path: "build/Porta.xcframework"),
        .target(
            name: "PortaKit",
            dependencies: ["CPorta"],
            linkerSettings: [
                .linkedFramework("CoreFoundation"),
                .linkedFramework("NetworkExtension"),
                .linkedFramework("Security"),
                .linkedFramework("SystemConfiguration"),
            ]
        ),
        .testTarget(name: "PortaKitTests", dependencies: ["PortaKit"]),
    ]
)
