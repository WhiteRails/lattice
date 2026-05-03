# Example 04 — Managing `*.lattice` domains on LatticeChain (English)

This example shows **how to manage on-chain namespaces** (`label.lattice`, canonical URI `lattice://label`) using TypeScript against `LatticeChain.sol`: issuer setup required by the contract, **full `registerNamespace` arguments**, **service binding updates**, **access policy updates**, and **read-only queries** including reserved slugs.

## Prerequisites

1. **Compile the contract** (ABI for `node/chain.ts`):

   ```bash
   npm run build:contracts
   ```

2. **JSON-RPC endpoint** (local Anvil/Hardhat node or any EVM network).

3. **A funded wallet private key** (hex, `0x…`). The same account is used as **contract owner** (governance) and, in this script, as **namespace registrar / admin** unless you pass a separate admin address.

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `LATTICE_RPC_URL` | No | Default `http://127.0.0.1:8545` |
| `LATTICE_CHAIN_PRIVATE_KEY` | **Yes** | Hex private key used to sign transactions |
| `LATTICE_CHAIN_ADDRESS` | No | Deployed `LatticeChain` address; if omitted, the script **deploys** a new contract (needs gas on that RPC) |
| `LATTICE_NAMESPACE_FQDN` | No | Override FQDN (must match `^[a-z0-9-]+\.lattice$`). Default is time-based to allow re-runs |
| `LATTICE_NAMESPACE_ADMIN` | No | Optional `namespaceAdmin` address (defaults to `address(0)` → registrar = `msg.sender` in Solidity) |

## Run

```bash
npm run example:domains
```

## What the script does (mapping to the contract)

| Step | Solidity / behavior | TypeScript (`node/chain.ts`) |
|------|----------------------|----------------------------|
| Deploy (optional) | `constructor` sets `owner`, seeds reserved slugs | `deployLatticeChain` |
| Cert types | `registerCertType` **onlyOwner** | `chainRegisterCertType` |
| Issuers | `registerIssuer` **onlyOwner** | `chainRegisterIssuer` |
| Issuer may issue type | `setIssuerPermission` **onlyOwner** | `chainSetIssuerPermission` |
| Register domain | `registerNamespace` — requires `issuers[ownerIssuerId].active` | `chainRegisterNamespace` |
| Change “where it points” | `updateNamespaceServiceBinding` — `namespaceAdmin` **or** `owner` | `chainUpdateNamespaceServiceBinding` |
| Firewall-style policy | `setNamespaceAccessPolicy` — same auth | `chainSetNamespaceAccessPolicy` |
| Read record | `namespaces(nameHash)` | `chainGetNamespace` |
| Reserved slug flag | `reservedOfficialLatticeSlugs(slugHash)` | `chainGetReservedOfficialSlug` |
| Governance (not run by default) | `setReservedOfficialSlug`, `transferOwnership`, checkpoints, freezes, … | `chainSetReservedOfficialSlug`, `chainTransferOwnership`, … |

### `registerNamespace` parameters (all options)

| Argument | Role |
|----------|------|
| `fqdn` | ASCII `*.lattice` single label; invalid → revert |
| `_ownerIssuerId` | `bytes32` from issuer **label** (must be an **active** issuer) |
| `_serviceCertHash` | Opaque `bytes32` commitment (e.g. service cert / gateway binding) |
| `_metadataHash` | Opaque `bytes32` (e.g. policy or metadata URI hash) |
| `_namespaceAdmin` | `address(0)` → defaults to caller; else explicit domain admin |
| `_publicAccess` | If `true`, gateways should skip credential-class gate (policy still documented for transparency) |
| `_credentialMask` | When `!publicAccess`: OR of `CRED_GOVERNMENT=1`, `CRED_ENTERPRISE=2`, `CRED_MODEL=4`; `0` + not public → deny-all at gateway |
| `_minAssuranceLevel` | Minimum `CertType.assuranceLevel` expected on client cert (gateway-enforced) |

## CLI equivalents (`npm run lattice -- …`)

```bash
# Issuer registry (owner key)
lattice chain cert-type register <name> --assurance <n> --rpc … --contract … --key-file …
lattice chain issuer register <label> <typeLabel> --public-key-hash <0x…> …
lattice chain issuer set-permission <issuer> <certType> --allow …

# Namespace (registrar key, or owner for reserved slugs)
lattice chain namespace register <fqdn> --owner-issuer <label> \
  [--namespace-admin 0x…] [--service-cert-hash 0x…] [--metadata-hash 0x…] \
  [--public | --credentials gov,enterprise,model] [--min-assurance <n>] …

lattice chain namespace update-service <fqdn> [--service-cert-hash 0x…] [--metadata-hash 0x…] …
lattice chain namespace set-policy <fqdn> [--public | --credentials …] [--min-assurance <n>] …
lattice chain namespace show <fqdn> …
```

## Gateway enforcement

On-chain data is only the **policy registry**. Entry/gateway nodes must apply `publicAccess` / `credentialMask` / `minAssuranceLevel` **before** forwarding to the backend. See [docs/Namespace-firewall-gateway.md](../../docs/Namespace-firewall-gateway.md) and `core/namespace-access.ts` (`clientMeetsNamespacePolicy`).

## Local node

For RPC at `http://127.0.0.1:8545` (the default in this example), start [Anvil](https://book.getfoundry.sh/anvil/) or any compatible dev chain, then run `npm run example:domains`.

## Other `onlyOwner` APIs (not exercised here)

Governance-only surfaces on the same contract include `transferOwnership`, `submitCheckpoint`, `anchorRevocation`, `setSubjectFreeze`, key/recovery/revocation registry helpers, and `setReservedOfficialSlug`. See `contracts/LatticeChain.sol` and the `chain*` helpers in `node/chain.ts`.
