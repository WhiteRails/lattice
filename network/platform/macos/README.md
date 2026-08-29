# macOS adapter

`PacketTunnelProvider` owns routes, MTU 1280 and the private `lattice` DNS
domain through NetworkExtension. The containing signed app must inject the Rust
LNP/1 packet engine through `LatticePacketEngineFactory`; without it the
extension returns `configurationInvalid` and does not create a partial tunnel.

The source package can be checked with `swift build`. Public installation still
requires an Apple Network Extension entitlement, app signing and notarization.
Per-app rules are applied only by an MDM-managed containing app; the provider
does not claim per-app isolation when the OS policy does not grant it.
