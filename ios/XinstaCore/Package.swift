// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "XinstaCore",
    platforms: [
        .iOS(.v16)
    ],
    products: [
        .library(
            name: "XinstaCore",
            targets: ["XinstaCore", "XinstaAdapter", "XinstaUI"]
        )
    ],
    targets: [
        .target(
            name: "XinstaCore",
            path: "Sources/Core",
            publicHeadersPath: "."
        ),
        .target(
            name: "XinstaAdapter",
            dependencies: ["XinstaCore"],
            path: "Sources/Adapter",
            publicHeadersPath: "."
        ),
        .target(
            name: "XinstaUI",
            dependencies: ["XinstaCore", "XinstaAdapter"],
            path: "Sources/UI",
            publicHeadersPath: "."
        ),
        .testTarget(
            name: "XinstaUIKitTests",
            dependencies: ["XinstaCore", "XinstaAdapter", "XinstaUI"],
            path: "Tests/XinstaUIKitTests"
        )
    ]
)
