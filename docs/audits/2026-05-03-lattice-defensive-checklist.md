# Lattice Defensive Checklist

Date: 2026-05-03

Legend:

- `Pass`: implemented and aligned with the current security claim
- `Partial`: some support exists, but the control is incomplete or easy to bypass
- `Fail`: the control is missing, misleading, or contradicted by the implementation

## 1. Agent identity and cryptographic binding

| Control | Pass condition | Status | Current evidence |
| --- | --- | --- | --- |
| Agent identity is bound to a cryptographic proof at ingress | Entry rejects unsigned or mismatched agent identities | `Fail` | `node/entry.ts:23-25,86-87` trusts `x-lattice-agent` and `LATTICE_AGENT` |
| Overlay messages are signed end to end | Relay/gateway verify message authenticity before routing | `Fail` | `node/message.ts:1-19`, `node/relay.ts:29-50`, `node/gateway.ts:27-38` |
| Agents retain signing keys for proof of possession | Created agents store private key material securely or use an external signer | `Fail` | `cli/lattice.ts:69-76`; observed `agents/bot1.json` stored no private key |
| Sample agent integrations follow a secure identity pattern | Reference clients do not rely on spoofable identity headers | `Fail` | `examples/agents/node-agent.js:23-26` sends `x-lattice-agent` directly |

## 2. Certificate issuance, persistence, and revocation

| Control | Pass condition | Status | Current evidence |
| --- | --- | --- | --- |
| CA root key is persisted across CLI invocations | `init` stores a reusable issuer state and later issuance reloads it | `Fail` | `cli/lattice.ts:44-48`, `cli/lattice.ts:69-76`, `core/ca.ts:27-30` |
| Signed certificates are stored as signed bundles | Persisted agent/service state includes cert, issuer metadata, and signature | `Fail` | `core/ca.ts:42-46`, `cli/lattice.ts:76` |
| Certificate registration verifies issuer signatures | Gateway rejects bare or altered certificate objects | `Fail` | `core/gateway.ts:38-42` only checks expiry/timestamps |
| Revocation is enforced on cert/key identity, not display name | Runtime revokes by certificate or key ID/hash everywhere | `Partial` | `node/state.ts:103-116` revokes agent names; `core/gateway.ts:66-69` uses cert hash only when configured |
| Fresh revocation proof gates critical actions | High-risk actions require a current signed freshness proof | `Fail` | `docs/lattice-whitepaper.md:766-768` requires it; runtime does not implement it |

## 3. Policy enforcement and approval gates

| Control | Pass condition | Status | Current evidence |
| --- | --- | --- | --- |
| Default deny is enforced at the service boundary | Unmatched requests are denied | `Pass` | `node/policy-loader.ts:69-92`, `node/gateway.ts:39-49` |
| Capability tokens enforce expiry and constraints | Gateway validates `expires_at`, customer scopes, limits, and approval flags | `Fail` | `core/gateway.ts:161-168`, `core/types.ts:96-108` |
| Delegation and intent scopes are enforced | Gateway checks `allowed_actions`, `forbidden_actions`, budgets, and expiry | `Fail` | `core/gateway.ts:48-73`; richer fields exist in `core/types.ts:71-94` |
| Human approval requirements are durable and explicit | High-risk paths always produce approval state before backend execution | `Partial` | `node/gateway.ts:45-48` returns `202`, but `services/gmail-proxy/index.ts:17-19` notes it only works if policy caught it upstream |
| Operator tooling reflects the real policy surface | Inspection and ping surfaces derive from the same source of truth as enforcement | `Partial` | `node/ping.ts:17-24` uses hardcoded action lists; `node/gateway.ts:96-102` infers actions from URL paths |

## 4. Runtime isolation and sandboxing

| Control | Pass condition | Status | Current evidence |
| --- | --- | --- | --- |
| `--no-internet` activates a stricter runtime mode | CLI passes the isolation flag to the runner correctly | `Fail` | `cli/lattice.ts:198-214`; validation showed `commander` exposes `internet`, not `noInternet` |
| Non-container mode prevents egress outside the proxy | Raw sockets and direct clients are blocked | `Fail` | `node/runner.ts:22-37` only injects environment variables |
| Container mode provides a tested isolated path | Docker execution is covered by tests and documented accurately | `Partial` | `node/runner.ts:40-56` supports Docker, but there is no validation in `tests/` and the flag plumbing is broken |
| Entry/relay/gateway listeners authenticate peers | Localhost reachability alone is not treated as trust | `Fail` | `node/entry.ts:59-83`, `node/relay.ts:19-64`, `node/gateway.ts:18-22` |

## 5. SAAE, logs, and proofs

| Control | Pass condition | Status | Current evidence |
| --- | --- | --- | --- |
| Envelopes hash the actual target, request, and response | No placeholder hashes remain in production paths | `Fail` | `core/gateway.ts:134-139`, `README.md:51-54` |
| Envelopes contain verifiable agent signatures | Gateway only accepts fully signed actions | `Fail` | `core/gateway.ts:147-152`, `core/envelope.ts:22-30` |
| Local logs are append-only and tamper-evident | Editing `actions.jsonl` is detectable | `Fail` | `node/state.ts:127-140`, `cli/lattice.ts:220-242` |
| Batch artifacts preserve the exact committed leaf set | Proof generation does not depend on the current mutable log file | `Fail` | `node/batch.ts:17-18,35-38,74-89` |
| Inclusion proofs map to a specific sealed batch | Proof roots remain stable after new entries | `Fail` | `core/log.ts:134-168` |
| Hashing implementation matches cryptographic claims | Merkle and envelope hashing use the documented algorithms | `Partial` | `README.md:41-45` claims `SHA3-512`; `core/envelope.ts:8-16` and `node/batch.ts:37` use SHA-256 |

## 6. Service gateway, relay, and registry security

| Control | Pass condition | Status | Current evidence |
| --- | --- | --- | --- |
| Routing decisions come from authenticated registry data | Overlay routing is not hardcoded to localhost ports | `Fail` | `node/entry.ts:12-14`, `node/relay.ts:12-17` |
| Service registration requires certificate material | `service add` stores a verifiable service identity, not just a URL | `Fail` | `cli/lattice.ts:117-123` |
| Trust checks validate certificates and revocation | `ping` reflects actual trust state | `Fail` | `node/ping.ts:41-43`, `cli/lattice.ts:246-272` |
| Backend forwarding strips untrusted caller-controlled transport headers | Gateways do not forward spoofable headers blindly | `Partial` | `node/gateway.ts:59-65` forwards `msg.payload.headers` directly to the backend |

## 7. Secret handling and local state

| Control | Pass condition | Status | Current evidence |
| --- | --- | --- | --- |
| Sensitive key material is stored intentionally and minimally | Only necessary keys are persisted, with a clear storage model | `Fail` | CA private key is not stored at all; agent private key is generated then dropped |
| Local state files have a hardening story | File permissions, integrity, and compromise assumptions are documented and enforced | `Fail` | `node/state.ts:23-140` creates and writes files with no integrity or permission checks |
| On-chain signing keys avoid argv exposure | Operators can use env vars, files, or external signers | `Fail` | `cli/lattice.ts:287-289`, `cli/lattice.ts:309-313` |

## 8. Supply chain and build hygiene

| Control | Pass condition | Status | Current evidence |
| --- | --- | --- | --- |
| Reproducible dependency resolution is present | Lockfile is committed and used in normal installs | `Pass` | `package-lock.json` is present |
| Dependency or advisory scanning is built into the repo workflow | Project scripts or CI include audit/scanning steps | `Fail` | `package.json:6-13` contains `test`, `build`, `lattice`, and service scripts only |
| Security-sensitive examples are labeled as examples, not guarantees | Sample/demo code does not read as production hardening | `Partial` | `examples/agents/node-agent.js` is a demo, but README claims broader security guarantees |

## 9. Documentation vs implementation

| Control | Pass condition | Status | Current evidence |
| --- | --- | --- | --- |
| Runtime commands in the README match the real CLI | Operators can follow the docs without silently losing controls | `Fail` | `README.md:96-99` says `gateway start`; CLI exposes `node start --role ...` in `cli/lattice.ts:173-195` |
| Threat-model claims reflect current enforcement | Docs distinguish MVP placeholders from enforced security properties | `Fail` | `README.md:30-60` and `docs/lattice-whitepaper.md:766-768,898-905` claim stronger guarantees than the code enforces |
| Project structure documentation matches the repo | Docs point to the actual runtime and SDK paths | `Fail` | `README.md:145-148` refers to `src/`, `daemon/`, and `cmd/`; repo uses `core/`, `node/`, and `cli/` |

## Suggested remediation order

1. Fix identity and isolation controls first:
   `F1`, `F2`, `F3`, `F4`, `F5`
2. Then fix certificate, authority, and envelope validation:
   `F6`, `F7`, `F8`, `F9`, `F10`
3. Then fix auditability and operator trust signals:
   `F11`, `F12`, `F13`, `F14`, `F15`
