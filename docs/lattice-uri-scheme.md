# Lattice official URI → on-chain namespace

Product convention (not a browser protocol handler in the MVP):

| URI | Canonical FQDN on LatticeChain | Who may `registerNamespace` |
|-----|-------------------------------|-----------------------------|
| `lattice://governments` | `governments.lattice` | **Contract owner only** (slug is *reserved official*) |
| `lattice://lattice` | `lattice.lattice` | **Contract owner only** |
| `lattice://echo` | `echo.lattice` | Any caller with gas, if slug is not reserved |

Rules enforced on-chain (`LatticeChain.sol`):

- FQDN must match ASCII lowercase `[a-z0-9-]+\\.lattice` (single label before `.lattice`).
- Reserved slugs (`governments`, `lattice`, `system`, `registry` by default) can only be registered by `owner`.
- Owner may add/remove reserved slugs via `setReservedOfficialSlug` (CLI: `lattice chain reserved set|show`).

Verifiers map `lattice://<slug>` → `<slug>.lattice` → `nameHash = keccak256(utf8(fqdn))` and read `namespaces(nameHash)`.

Each record includes **`namespaceAdmin`** (puede actualizar *binding* `serviceCertHash` / `metadataHash` y la política de acceso), **`publicAccess`**, **`credentialMask`** (OR de clases de certificado cliente: gobierno / empresa / modelo) y **`minAssuranceLevel`**. La cadena solo **registra** la política; el **gateway / entry** debe aplicarla antes de llegar al host (ver [Namespace-firewall-gateway.md](./Namespace-firewall-gateway.md)).

CLI: `lattice chain namespace register|update-service|set-policy|show`.
