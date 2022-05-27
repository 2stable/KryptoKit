// swift-tools-version:5.3
import PackageDescription

let package = Package(
    name: "KryptoKit",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13)
    ],
    products: [
        .library(name: "KryptoKit", targets: ["KryptoKit"])
    ],
    dependencies: [
        .package(name: "Sodium", url: "https://github.com/jedisct1/swift-sodium.git", from: "0.9.0")
    ],
    targets: [
        .target(
            name: "KryptoKit",
            dependencies: [
                "Sodium"
            ],
            path: "Sources"
        )
    ]
)
