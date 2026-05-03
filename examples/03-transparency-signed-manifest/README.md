# Example 3 — Signed issuer manifest + transparency log + on-chain checkpoint

This example shows the pattern you asked for: **do not trust the download URL alone** — trust **(1) a governance signature** over canonical manifest bytes, **(2) an append-only Merkle transparency log** that commits the manifest content hash, and **(3) the same Merkle root** as input to `submitCheckpoint()` on `LatticeChain` (see `node/chain.ts`).

## Flow

1. **Bootstrap** — You obtain the governance **public key** out-of-band (OS image, hardware vendor, multisig ceremony, etc.). Same role as a Web PKI trust anchor.
2. **Manifest** — JSON document lists `issuer_id` → `public_key` → `allowed_cert_types`. Bytes are canonicalized with `stableStringify()` before signing/hashing.
3. **Signature** — Governance private key signs `stableStringify(manifest)` (`signTrustManifest` / `verifyTrustManifestSignature`).
4. **Transparency log** — An `issuer_manifest_committed` registry event is appended to `LatticeLog`; `computeBatch()` seals a Merkle root and the log operator signs the batch (`BatchCommitment`).
5. **On-chain checkpoint** — Call `submitCheckpoint(batch, rpc, key, contract)` with the same `merkle_root` and batch metadata so verifiers can compare off-chain batch files with chain state (`verifyCheckpointOnChain`).

If `governments.lattice` (or any mirror) is compromised but **signing keys and/or chain governance** are not, tampering is detectable: wrong signature, wrong hash, or Merkle / chain mismatch.

## Run

```bash
npm run example:manifest
```

Deploying the contract is optional for this demo; the script prints the payload you would anchor.
