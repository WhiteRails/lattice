# Namespace policy as a DNS-level firewall

Lattice namespaces (`*.lattice`, canonical URI `lattice://<slug>`) store **routing commitments** (`serviceCertHash`, `metadataHash`) and an **access policy** on `LatticeChain`:

| Field | Meaning |
|-------|--------|
| `namespaceAdmin` | Domain owner (may change routing + policy; defaults to registrar). |
| `publicAccess` | If `true`, gateways accept any client that passes overlay/crypto transport rules. |
| `credentialMask` | If `!publicAccess`, OR of accepted **client credential classes**: `1` government, `2` enterprise, `4` model provider. |
| `minAssuranceLevel` | Minimum `CertType.assuranceLevel` on the presented client certificate (0 = none). |

## Enforcement point

The **Entry node / relay / gateway** MUST, before forwarding to the backend host:

1. Resolve `nameHash` from the requested FQDN.
2. Read `namespaces(nameHash)` from the chain (or a cached, signed mirror).
3. If `!publicAccess`, verify the client presents a valid cert chain mapping to at least one bit in `credentialMask`, and meets `minAssuranceLevel`.
4. Only then forward to the HTTP/WebSocket backend described by off-chain metadata bound to `serviceCertHash` / `metadataHash`.

This is **not** implemented inside `LatticeChain.sol` (no user traffic hits the contract); the contract is the **policy registry**. The runtime is responsible for “firewall before host”.

## Solidity constants

- `CRED_GOVERNMENT = 1`
- `CRED_ENTERPRISE = 2`
- `CRED_MODEL = 4`

Combine with OR, e.g. `7` = accept any of the three classes.
