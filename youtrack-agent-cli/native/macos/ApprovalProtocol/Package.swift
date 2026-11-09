// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "ApprovalProtocol",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .library(name: "ApprovalProtocol", targets: ["ApprovalProtocol"]),
    ],
    targets: [
        .target(name: "ApprovalProtocol"),
        .testTarget(name: "ApprovalProtocolTests", dependencies: ["ApprovalProtocol"]),
    ]
)
