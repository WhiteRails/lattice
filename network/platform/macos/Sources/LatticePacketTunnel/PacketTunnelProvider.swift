import Foundation
import NetworkExtension

public protocol LatticePacketEngine: AnyObject {
    /// Verifies the signed LNP/1 profile, its freshness, pins and platform
    /// policy. It returns the only settings the host is allowed to install.
    func verifiedTunnelSettings(profile: Data) throws -> Data
    func start(profile: Data, packetFlow: NEPacketTunnelFlow, completion: @escaping (Error?) -> Void)
    func stop()
}

public enum LatticePacketEngineFactory {
    /// The signed app target installs the Rust LNP/1 engine factory at launch.
    /// An unsigned or incomplete bundle therefore fails closed.
    public static var make: (() -> LatticePacketEngine?)?
}

public final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var engine: LatticePacketEngine?

    public override func startTunnel(
        options: [String: NSObject]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        guard
            let configuration = protocolConfiguration as? NETunnelProviderProtocol,
            let provider = configuration.providerConfiguration,
            let signedProfile = provider["signedProfile"] as? Data,
            let engine = LatticePacketEngineFactory.make?()
        else {
            completionHandler(NEVPNError(.configurationInvalid))
            return
        }

        let settings: TunnelSettings
        do {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            let verifiedSettings = try engine.verifiedTunnelSettings(profile: signedProfile)
            settings = try decoder.decode(TunnelSettings.self, from: verifiedSettings)
            guard settings.mtu == 1280,
                  settings.mode == "split" || settings.mode == "full",
                  settings.signedStateValidUntil.timeIntervalSinceNow > 0,
                  !settings.gatewayAddress.isEmpty,
                  !settings.dnsServers.isEmpty
            else {
                throw NEVPNError(.configurationInvalid)
            }
        } catch {
            engine.stop()
            completionHandler(error)
            return
        }

        let network = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: settings.gatewayAddress)
        network.mtu = NSNumber(value: settings.mtu)
        if let ipv4 = settings.ipv4 {
            let ipv4Settings = NEIPv4Settings(addresses: [ipv4.address], subnetMasks: [ipv4.netmask])
            ipv4Settings.includedRoutes = settings.mode == "full"
                ? [NEIPv4Route.default()]
                : settings.ipv4Routes.map { NEIPv4Route(destinationAddress: $0.address, subnetMask: $0.netmask) }
            ipv4Settings.excludedRoutes = [NEIPv4Route(destinationAddress: settings.gatewayAddress, subnetMask: "255.255.255.255")]
            network.ipv4Settings = ipv4Settings
        }
        if let ipv6 = settings.ipv6 {
            let ipv6Settings = NEIPv6Settings(addresses: [ipv6.address], networkPrefixLengths: [NSNumber(value: ipv6.prefix)])
            ipv6Settings.includedRoutes = settings.mode == "full"
                ? [NEIPv6Route.default()]
                : settings.ipv6Routes.map { NEIPv6Route(destinationAddress: $0.address, networkPrefixLength: NSNumber(value: $0.prefix)) }
            network.ipv6Settings = ipv6Settings
        }
        let dns = NEDNSSettings(servers: settings.dnsServers)
        dns.matchDomains = ["lattice"]
        dns.matchDomainsNoSearch = true
        network.dnsSettings = dns

        setTunnelNetworkSettings(network) { [weak self] error in
            guard error == nil else { completionHandler(error); return }
            guard let self else {
                engine.stop()
                completionHandler(NEVPNError(.configurationInvalid))
                return
            }
            self.engine = engine
            engine.start(profile: signedProfile, packetFlow: self.packetFlow) { [weak self] engineError in
                if engineError != nil { engine.stop(); self?.engine = nil }
                completionHandler(engineError)
            }
        }
    }

    public override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        engine?.stop()
        engine = nil
        completionHandler()
    }
}

private struct TunnelSettings: Decodable {
    struct IPv4: Decodable { let address: String; let netmask: String }
    struct IPv6: Decodable { let address: String; let prefix: UInt8 }
    let gatewayAddress: String
    let mtu: UInt16
    let mode: String
    let signedStateValidUntil: Date
    let ipv4: IPv4?
    let ipv6: IPv6?
    let ipv4Routes: [IPv4]
    let ipv6Routes: [IPv6]
    let dnsServers: [String]

    enum CodingKeys: String, CodingKey {
        case gatewayAddress = "gateway_address"
        case mtu, mode
        case signedStateValidUntil = "signed_state_valid_until"
        case ipv4, ipv6
        case ipv4Routes = "ipv4_routes"
        case ipv6Routes = "ipv6_routes"
        case dnsServers = "dns_servers"
    }
}
