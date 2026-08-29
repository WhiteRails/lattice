# OS adapter contract

| Capability | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Global packet tunnel | TUN + `lattice-netd` | `NEPacketTunnelProvider` host | `IVpnPlugIn` host |
| Split/full routes | Implemented | Host source | Host source |
| Private DNS routing | systemd resolver unit | `NEDNSSettings.matchDomains` | VPN domain assignment in signed host |
| Kill switch | nftables | NetworkExtension route enforcement | VPN route/traffic filters |
| Per-agent/app | network namespace, lease | Only managed per-app policy | Only verified traffic filter policy |
| `lttc:` handler | `.desktop` | `CFBundleURLTypes` | MSIX Protocol |
| Public installer | Linux bundle | Blocked on signing/entitlement | Blocked on signing/MSIX identity |

The platform host owns OS routing and DNS; the Rust engine owns profile
verification, QUIC/mTLS, pins, fragmentation and policy. A host without the
linked engine must reject tunnel startup. macOS and Windows must reject
per-agent mode unless the OS reports that the intended app policy is installed
and active.

Before either host installs routes, DNS or packet callbacks, its linked engine
must verify the signed profile and return platform settings derived from that
verification. A missing engine, invalid profile, expired state or callback
after engine teardown terminates the tunnel rather than accepting or leaking
packets.

Linux per-agent mode creates a dedicated namespace and a private veth underlay,
then starts `lattice-netd` and `lattice-resolver` inside it. The agent output
chain allows only loopback, its TUN and the signed Gateway UDP tuple. The host
forward chain and NAT exist only for the namespace lifetime; the process is
dropped to the invoking sudo UID/GID with no supplementary groups and
`no_new_privs`.

macOS source lives under `network/platform/macos`; it requires the Network
Extension entitlement and a containing app. Windows source and manifest live
under `network/platform/windows`; its MSIX requires `networkingVpnProvider`.
Unsigned sources are integration artifacts, not publicly installable releases.
