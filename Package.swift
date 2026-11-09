// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "OpenPlanCore",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [.library(name: "OpenPlanCore", targets: ["OpenPlanCore"])],
    targets: [
        .target(name: "OpenPlanCore"),
        .testTarget(name: "OpenPlanCoreTests", dependencies: ["OpenPlanCore"]),
    ]
)
