// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "LatticePacketTunnel",
    platforms: [.macOS(.v13)],
    products: [.library(name: "LatticePacketTunnel", targets: ["LatticePacketTunnel"])],
    targets: [.target(name: "LatticePacketTunnel")]
)
