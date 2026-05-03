# Example 1 — Government issues a certificate to a citizen

## How do we ensure only real governments can issue “government” certificates?

In the full protocol (see `docs/trust-model.md`, **LatticeChain / IssuerRegistry**):

1. **Federated trust anchor** — Verifiers do not trust an `issuer` string by itself. They trust a **registry** (e.g. the `IssuerRegistry` contract) that binds each authorized `issuer_id` to a **public-key hash** (or raw key material, depending on design) and the **certificate types** that issuer is allowed to sign.
2. **Cryptographic chain** — Each certificate carries `issuer` and a CA signature (`ca_signature`). An attacker can mint `issuer: gov:…`, but if their key is **not** in the registry, or they are not allowed to sign `GovernmentHumanCert` / identity-class `AgentCert`, **verification fails**.
3. **Two attacks covered**:
   - **Unknown CA** (`gov:scam:…`) → not present in the trusted-issuer map.
   - **Same name, different key** → signature does not verify against the registered public key for that `issuer_id`.

This MVP repo does not deploy the chain; `scenario.ts` simulates the registry with an in-memory `Map` — the same idea as **IssuerRegistry**, without trusting the issuer string alone.

## Certificate “in the name of Elon Musk”

The demo issues an `AgentCert` signed by a sample government CA (fictional subject `agent:citizen:elon-musk-demo`). In production you would use a **GovernmentHumanCert** type with privacy compartments; here we only illustrate **issuance + verification** against the registry.

For **signed downloadable manifests**, Merkle transparency batches, and the **on-chain checkpoint hook**, see [Example 03](../03-transparency-signed-manifest/).
