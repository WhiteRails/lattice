# Lattice Protocol — Trust Model & Post-Quantum Spec

The Lattice Protocol implements the **Traceveil Trust Chain**, moving beyond a simple "who are you" identity model into a full **Multi-Issuer Agent PKI** optimized for autonomous AI, coupled with **Post-Quantum Cryptographic Agility** and **Selective Accountability**.

## 1. Multi-Issuer Agent PKI

Lattice separates *identity authority* from *action authority*. An action isn't just approved by "a certificate"; it is validated by a **Chain of Trust**.

### Certificate Types
- **UserCert**: Self-asserted by a human for low-risk personal agents.
- **GovernmentHumanCert**: Issued by a Government CA (`gov:ar:digital-identity-ca`), providing verifiable legal identity without exposing the subject publicly (see Privacy Model).
- **EnterpriseApproverCert**: Issued by an Enterprise CA (`org:acme:enterprise-ca`), authorizing a human to act on behalf of the organization.
- **ModelProviderCert**: Issued by an AI provider (e.g., Anthropic, OpenAI). Certifies the provenance of the model, safety profile, and retains an encrypted hash of the prompt for auditability.
- **AgentCert**: Issued by the owner to a specific autonomous agent, granting predefined capabilities.
- **ToolCert**: Certifies the authenticity of the tools/APIs being invoked.

### Trust Federation (LatticeChain)
Instead of trusting global centralized root CAs, Lattice relies on a federated smart contract infrastructure (`LatticeChain.sol`) acting as the Trust Registry.
1. **IssuerRegistry**: Defines which CA is allowed to issue which Certificate Type.
2. **NamespaceRegistry**: Maps stable names / name hashes to a **subject** (stable ID), not to a single permanent key.
3. **KeyRegistry**: Public key material per subject, by `key_id`, purpose, validity window, and lifecycle status (`ACTIVE` … `REVOKED_COMPROMISED`).
4. **RecoveryRegistry**: Threshold recovery policies (who may rotate or revoke keys, with optional timelocks).
5. **RevocationRegistry**: Key and certificate revocation events, including compromise windows and evidence commitments (hashes only on-chain).
6. **CheckpointRegistry**: Merkle roots for transparency logs and revocation sets.
7. **GovernanceRegistry**: Subject freeze (emergency), timelocked governance operations, and high-threshold emergency paths.

Legacy Merkle-based **RevocationRootRegistry** checkpoints remain the transparency anchor for bulk revocation sets; per-key lifecycle events are additionally queryable for verifiers.

## 2. Post-Quantum Cryptographic Agility

Relying on hardcoded RSA or ECDSA in an AI-driven network is a severe vulnerability. Lattice is built with "crypto-agility" from v0, implementing NIST post-quantum standards.

### Hybrid Handshakes
Overlay Network transport (`lp://`) uses a hybrid Key Encapsulation Mechanism (KEM):
- Classical: `X25519` or `ECDH`
- Post-Quantum: `ML-KEM-768` (FIPS 203)
- `shared_secret = KDF(classical_secret || pq_secret)`

### Post-Quantum Signatures
Actions and Certificates define their cryptographic suite. A single certificate can hold multiple keys.
- Legacy/Low Assurance: `Ed25519`
- Standard Assurance: `ML-DSA-65` (FIPS 204)
- High Assurance / Root CAs: `ML-DSA-87` + `SLH-DSA` (hash-based backup)

### Hash Agility
Since SHA-256's effective security is halved by Grover's algorithm, Lattice uses `SHA3-512` or `BLAKE3` for long-term Merkle Trees and transparency log action hashing.

## 3. Privacy & Selective Accountability

Lattice achieves accountability without becoming a panopticon by enforcing **Compartmentalized Evidence** and **Threshold Decryption**.

### Government-Sealed Identity Certificates
A government-issued human certificate should not expose the citizen’s legal identity on-chain. It publishes only a verifiable commitment and issuer signature, while sealing the legal identity inside an encrypted disclosure payload that can be opened only under predefined legal or multi-party conditions (e.g., 2-of-4 threshold: Government + Judge + Auditor + User).

### Compartmentalized Evidence Envelopes
*Traceveil uses compartmentalized evidence: each issuer or participant can decrypt only the evidence required to verify its own claim. A model provider may verify model provenance without learning the user’s legal identity; a government may reveal legal identity under due process without accessing model-private telemetry; an enterprise may audit authorization without seeing unrelated personal data.*

In the Signed Agent Action Envelope (SAAE):
- **User/Gov Compartment**: Only accessible by Gov/Judge. Contains legal identity commitments.
- **Enterprise Compartment**: Only accessible by Corporate Auditors. Contains role and internal authorization.
- **Model Provider Compartment**: Only accessible by Model Provider. Contains executed prompts, model telemetry, and safety configs.
- **Tool Compartment**: Only accessible by the Tool Provider (e.g., Stripe). Contains request payloads and response hashes.

### Anti-Correlation (Pairwise Pseudonyms)
To prevent cross-domain tracking, agents generate pairwise, domain-specific identifiers using HMACs (e.g., `user_ref_for_openai`, `user_ref_for_stripe`). Public keys and global identifiers are not reused across contexts.

## 4. Stable Subject & Key Lifecycle (Traceveil)

**Invariant:** No critical identity may depend on a single permanent key.

| Layer | Role |
|--------|------|
| Stable subject | `did:traceveil:…` (or protocol-internal `subject_id`): persists for the life of the entity. |
| Keys | Rotatable, **purpose-specific**; multiple keys per subject with explicit lifecycle. |
| Certificates | Short-lived, re-issuable; bind claims to keys and subjects for a bounded time. |
| Delegations | Shorter and narrower than certs; revocable when keys rotate or compromise is declared. |
| Logs / checkpoints | Immutable history; verifiers re-evaluate past signatures against key state **at the time of signing**. |

### 4.1 Key purposes (do not merge roles)

Each subject SHOULD maintain distinct material (or explicitly labeled keys) for:

- **SIGNING** — certificates and operational actions.
- **ENCRYPTION** — decrypting evidence compartments (often distinct from signing).
- **RECOVERY** — authorizes planned rotation and high-threshold emergency rotation.
- **REVOCATION** — fast path to revoke operational keys.
- **AUDIT** — verify/log only; MUST NOT authorize high-risk actions alone.
- **COLD_ROOT** — offline; root-of-trust for recovering or rotating authorities.

Using one key for several purposes without declaration is **non-conformant**.

### 4.2 Normative transparency events (off-chain log + optional on-chain anchor)

- **`KEY_ROTATION`** — `old_key_id`, `new_key_id`, `effective_at`, `old_key_valid_until`, `signed_by` (e.g. old signing key + recovery quorum). Old key remains valid only until `old_key_valid_until`, then moves to `DEPRECATED` → `RETIRED`.
- **`EMERGENCY_KEY_COMPROMISE`** — compromised key marked `REVOKED_COMPROMISED`, `compromise_window`, `new_key_id`, `requires_reaudit`, `signed_by` recovery quorum with threshold metadata.
- **`FREEZE_SUBJECT`** — `effect`: block new cert issuance, block high-risk actions (e.g. L4/L5), allow read-only verification; signed by recovery quorum as policy dictates.

Government CA hierarchy (offline root, intermediates, HSM) follows the same separation: compromise of an intermediate is a **`GOV_CA_COMPROMISE`**-class event (freeze issuance, re-issue chain, review certs in the suspected window).

### 4.3 Historical signatures after revocation

When a key is revoked:

- **`REVOKED_RETIRED` / retired path** — key MUST NOT be used for new actions; **past** signatures remain cryptographically verifiable if the key was valid and not revoked at the action timestamp.
- **`REVOKED_COMPROMISED`** — signatures in the declared **compromise window** are not automatically void (that would break accounting and contracts); they become **`valid_but_contested`** or **`requires_secondary_proof`** per verifier policy.

Verifier predicate (conceptual):

```
valid
  := sig_ok
  AND key_valid_at(action_time)
  AND NOT revoked_before(action_time)
  AND NOT (key is COMPROMISED AND action_time in compromise_window)

if in compromise_window → valid_but_contested or requires_secondary_proof
```

### 4.4 Certificate and token lifetimes (damage containment)

- Root / cold: long-lived, offline.
- Intermediates: months–years, HSM.
- Leaf certs: days–weeks.
- Action / capability tokens: minutes–hours.
- Model invocation attestations: per-request or short batch.

### 4.5 Recovery timelocks

- Normal rotation: subject to timelock (e.g. 24–72h for user/enterprise profiles).
- Emergency **revocation** of a compromised operational key: immediate once policy witnesses are satisfied.
- Emergency **replacement** of root-tier keys: high threshold, may still use timelock where theft of recovery set is a concern.

### 4.6 Encryption compartments

Evidence uses **encryption key ids** and optional **period** labels. Loss of an encryption key implies loss of confidentiality for past ciphertexts unless multi-recipient or threshold escrow was configured. Compromise of an encryption key requires: revoke that key, rotate recipients, re-encrypt active material, mark historical ciphertext as **`potentially_exposed`** where policy requires.

### 4.7 Actor profiles (minimum expectations)

- **User** — e.g. 2-of-3 among device, hardware/passkey, recovery phrase / guardian / optional gov-backed recovery; user key leak revokes operational user keys, invalidates active delegations, requires re-authorization of personal agents; historical actions tagged per compromise rules.
- **Enterprise** — multisig (e.g. 3-of-5), HSM/KMS for operational keys, **freeze** of org namespace on suspected signing-key leak, mandatory audit for high-risk tiers during recovery.
- **Government** — offline root, intermediates, ceremonies, threshold governance, public bulletin + witnesses; root compromise triggers cross-registry and legal procedures (out of band to this spec).
- **Model provider** — short-lived online signing keys for model attestation; frequent rotation; compromise invalidates **new** claims after `confirmed_at` while preserving verifiable history before compromise where possible.

### 4.8 Protocol phrase (normative English / Spanish)

**EN:** Traceveil identities are stable, but their keys are disposable. Every user, enterprise, model provider, tool provider, and government authority maintains purpose-specific keys with explicit lifecycle states. Compromise does not destroy identity; it triggers revocation, rotation, re-issuance, audit, and policy-based treatment of historical signatures.

**ES:** Las identidades de Traceveil son estables, pero sus claves son descartables. Cada usuario, empresa, proveedor de modelo, herramienta y gobierno mantiene claves por propósito con estados explícitos de ciclo de vida. Una filtración no destruye la identidad: activa revocación, rotación, reemisión, auditoría y tratamiento diferenciado de firmas históricas.

**Contract (one line):** *Identity is permanent; keys are replaceable; certificates are short-lived; delegations are narrower still; actions are auditable forever.*

## Summary
*Traceveil separates identity authority from action authority. A user may issue personal agents, an enterprise may issue organizational authority, a government may issue legal-human identity, and a model provider may issue model provenance. No actor can self-promote into a higher trust class without being recognized by the federated trust registry. Stable subjects, rotatable keys, and explicit compromise and freeze semantics are first-class parts of that trust chain.*
