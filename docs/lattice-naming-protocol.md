# Lattice Naming Protocol v0.1

Lattice separates the network, the protocol used to enter it, participant
identity, registered names and current transport routes.

| Namespace | Meaning | Authority | Example |
| --- | --- | --- | --- |
| `lttc://` | Deep-link protocol | URI handler | `lttc://alice.coral/` |
| `*.coral` | Sovereign participant identity and delegated services | Signing identity | `alice.coral`, `api.alice.coral` |
| `<base32-key>.coral` | Canonical cryptographic identity | Embedded public-key commitment | `ghatg6z7...4aq.coral` |
| `*.reef` | Registered name | LatticeChain | `clipma.reef` |
| `*.lattice` | Lattice infrastructure | Lattice operators | `resolver.lattice` |

The canonical identity is the cryptographic name. Human names are signed
aliases and delegated service names; they do not replace the key. A `.reef`
name may delegate to a `.coral` identity, and a service such as
`wallet.clipma.reef` or `api.alice.coral` may resolve to any current route
announced by a signed LNP/1 profile.

The IP address, QUIC endpoint, relay and transport mode are never identity.
They are replaceable route data:

```text
clipma.reef
    -> chain delegation
alice.coral
    -> signed discovery/profile
current IPv4/IPv6 route, Gateway or relay
```

`lttc://` accepts canonical identities, Coral names, Reef names and explicit
Lattice infrastructure names. It validates the target and opens only the
corresponding HTTPS host; it never carries credentials, ports or an IP literal.
The legacy `lattice://` and `lp://` schemes are rejected by the LNP/1 runtime.

DNS remains private and fail-closed. `lattice-resolver` serves only names in a
verified profile for `.lattice`, `.coral` and `.reef`; unknown private names are
NXDOMAIN and public names are REFUSED. TLS pins and profile signatures, not DNS,
establish authority.
