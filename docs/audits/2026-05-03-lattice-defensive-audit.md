# Lattice Defensive Audit

Date: 2026-05-03

## Scope and method

This audit focuses on the code that currently defines Lattice's real trust boundary:

- Runtime and isolation in `node/runner.ts`, `node/entry.ts`, `node/relay.ts`, and `node/gateway.ts`
- Identity, certificates, and authority in `core/identity.ts`, `core/ca.ts`, `core/gateway.ts`, and `node/state.ts`
- Policies and authorization in `node/policy-loader.ts`, `core/policy.ts`, `cli/lattice.ts`, and `node/ping.ts`
- Logs, envelopes, batching, and trust anchoring in `core/log.ts`, `core/envelope.ts`, `node/batch.ts`, and `node/chain.ts`
- Operator-facing trust signals in `README.md`, `docs/lattice-whitepaper.md`, and the CLI

Baseline observed during this review:

- `npm test` passed: 29 tests across 6 test files
- `npm run build` completed successfully
- Several core guarantees are documented, but the current MVP often relies on local trust, placeholders, or unauthenticated metadata instead of cryptographic enforcement

## Priority summary

| Severity | Count | Themes |
| --- | --- | --- |
| `P0` | 5 | Identity spoofing, overlay bypass, isolation failures, broken root of trust |
| `P1` | 7 | Missing signature verification, missing authority enforcement, mutable audit trail |
| `P2` | 3 | Misleading trust tooling, hardcoded routing trust, secret handling UX |

## Detailed findings

### F1. `P0` Agent identity is taken from a user-controlled header without cryptographic binding

- Severity: `P0`
- Component: Entry runtime identity handling
- Preconditions: The attacker can reach the EntryNode HTTP listener or control code running inside the agent process.
- Abuse path: Send requests with an arbitrary `x-lattice-agent` header. The entry node copies that value into `OverlayMessage.source` and treats it as the caller identity.
- Impact: Any active agent identity can be impersonated. Revocation, policy, and audit attribution become dependent on a spoofable string instead of proof of possession.
- Evidence:
  - `node/entry.ts:23-25` and `node/entry.ts:86-87` derive the agent identity from `x-lattice-agent` or `LATTICE_AGENT`.
  - `node/entry.ts:40-49` copies that value directly into the overlay message.
  - `examples/agents/node-agent.js:23-26` shows the intended client behavior is to set the header directly.
  - Validation: a local request to `EntryNode` with `x-lattice-agent: spoofed-agent` returned `403 {"error":"Agent revoked"}` when `spoofed-agent` existed in a temporary revocation list, proving the header controls identity.
- Mitigation: Bind requests to an agent-held private key or mTLS identity and reject unsigned or mismatched identities at the entry point.
- Suggested test: Start `EntryNode`, issue two requests with different `x-lattice-agent` values, and assert the runtime rejects unsigned identity changes instead of accepting them.

### F2. `P0` Relay and gateway sockets accept unauthenticated local clients

- Severity: `P0`
- Component: Overlay transport ingress
- Preconditions: The attacker can open a localhost WebSocket connection to the relay or a service gateway.
- Abuse path: Connect directly to `RelayNode` or `ServiceGateway`, send a crafted `OverlayMessage`, and set `source` to any victim agent.
- Impact: A local process can bypass the entry node entirely, inject requests into the overlay, and impersonate agents or services without touching the official runtime.
- Evidence:
  - `node/relay.ts:19-24` accepts any localhost WebSocket client.
  - `node/relay.ts:29-50` parses JSON and routes it without authenticating the sender.
  - `node/gateway.ts:18-22` accepts any localhost WebSocket client.
  - `node/gateway.ts:27-38` trusts `msg.source` and immediately evaluates policy against that string.
  - `node/message.ts:1-19` defines the transport message as an unauthenticated data structure with no signature fields.
- Mitigation: Require authenticated channels between entry, relay, and gateway, and bind overlay messages to signed envelopes that are validated hop by hop.
- Suggested test: Open a raw WebSocket connection to a gateway port, send a forged `OverlayMessage`, and assert the gateway rejects the message before policy evaluation.

### F3. `P0` The `--no-internet` CLI flag is wired incorrectly and is silently ignored

- Severity: `P0`
- Component: CLI isolation control
- Preconditions: The operator relies on `lattice run --no-internet` to enforce a stricter runtime mode.
- Abuse path: Pass `--no-internet`; `commander` stores the option as `internet`, but the CLI reads `opts.noInternet`, so the runtime never receives the user's intent.
- Impact: The advertised isolation control does not activate. In practice, the warning path and Docker network restriction are skipped.
- Evidence:
  - `cli/lattice.ts:198-214` defines `--no-internet` but passes `opts.noInternet`.
  - `node/runner.ts:22-25` and `node/runner.ts:40-45` only act on `opts.noInternet`.
  - Validation: `node -e "..."` with the same `commander` definition returned `{"internet":false}` after parsing `--no-internet`, confirming `noInternet` is not the option key.
- Mitigation: Rename the option to a positive form such as `--isolate-network`, or read `opts.internet === false` explicitly and cover it with unit tests.
- Suggested test: Add a CLI parsing test that asserts `--no-internet` causes `runAgent()` to receive a truthy isolation flag.

### F4. `P0` The non-Docker execution path only injects proxy environment variables

- Severity: `P0`
- Component: Runtime network isolation
- Preconditions: The attacker controls agent code or can influence the HTTP client it uses.
- Abuse path: Ignore `HTTP_PROXY` and open raw TCP sockets or direct HTTP clients that do not honor proxy environment variables.
- Impact: The agent can bypass Lattice entirely, reach the open internet, and avoid policy enforcement and logging.
- Evidence:
  - `node/runner.ts:22-37` only sets proxy-related environment variables and `LATTICE_AGENT`.
  - `README.md:30-33` describes a default-deny proxy firewall and sandboxed agents.
  - `README.md:101-104` describes `run --no-internet` as a secure execution path.
  - Validation: running `lattice run --agent bot1 --no-internet -- node -e ...` only exposed proxy-related environment variables (`HTTP_PROXY`, `LATTICE_AGENT`, `NO_PROXY`) to the child process.
- Mitigation: Treat non-Docker mode as development-only, label it accordingly, and implement actual sandboxing or egress controls before calling it secure.
- Suggested test: Run an agent that opens a raw socket directly to a public host and assert that the runtime blocks the connection outside the proxy path.

### F5. `P0` The local CA root of trust is not persisted and later issuance uses a fresh random CA key

- Severity: `P0`
- Component: Certificate authority lifecycle
- Preconditions: The operator uses `lattice init` and later creates agents or services.
- Abuse path: `init` stores only a public key. Later `agent create` instantiates a brand-new `LatticeCA('ca.local')`, which generates a different private key and signs certificates with an unrelated CA instance.
- Impact: There is no stable issuer key, no consistent chain of trust, and no reliable way to verify that future certificates came from the CA initialized on disk.
- Evidence:
  - `cli/lattice.ts:44-48` stores only `{ caId, publicKey, createdAt }`.
  - `core/ca.ts:27-30` generates a fresh Ed25519 key pair in every `LatticeCA` constructor call.
  - `cli/lattice.ts:69-76` creates a new `LatticeCA('ca.local')` during `agent create` instead of loading the initialized CA.
  - `node/state.ts:39-46` supports loading `ca.json`, but the CLI never uses it to reconstruct the issuer.
  - Validation: a temporary `ca.json` created by `lattice init` contained only the public key; no private key or signed CA record was persisted.
- Mitigation: Persist the CA private key securely, store a signed CA certificate, and always reconstruct the same issuer state for later certificate issuance and verification.
- Suggested test: Initialize once, issue two agent certs in separate CLI invocations, and assert both verify under the same persisted CA key.

### F6. `P1` Agent private keys and signed certificate material are discarded during `agent create`

- Severity: `P1`
- Component: Agent identity material management
- Preconditions: The operator creates an agent and expects it to sign actions later.
- Abuse path: `agent create` generates a key pair but only saves the public key and unsigned certificate fields to disk.
- Impact: Agents cannot prove possession of their private key, and the runtime has no durable signed certificate package to validate later.
- Evidence:
  - `cli/lattice.ts:69-76` generates keys and saves only `{ cert, publicKey, createdAt }`.
  - `core/ca.ts:42-46` produces a `SignedCert` that includes `ca_signature`, but the CLI drops it.
  - Validation: the temporary `agents/bot1.json` file contained the public key and certificate fields only; no private key and no `ca_signature`.
- Mitigation: Persist agent private keys securely, store the full signed certificate bundle, and define a proof-of-possession flow for agent requests.
- Suggested test: After `agent create`, load the persisted agent material and verify it can sign and verify a challenge tied to the stored certificate.

### F7. `P1` Gateway registration and mediation do not verify certificate signatures or request signatures

- Severity: `P1`
- Component: SDK gateway mediation path
- Preconditions: An attacker can supply an `AgentCert` object to the gateway or reach code that calls `mediateToolCall`.
- Abuse path: Register a forged certificate with a plausible `agent_id`, then invoke the gateway with arbitrary `agent_signature`, delegation, intent, and capability objects.
- Impact: The gateway trusts unsigned or self-asserted inputs, so identity and authority checks collapse to string comparisons and expiry checks.
- Evidence:
  - `core/gateway.ts:38-42` only checks `isCertValid(cert)` before registration.
  - `core/identity.ts:81-90` defines validity as timestamp checks only.
  - `core/gateway.ts:48-73` accepts an `agent_signature` parameter but never verifies it.
  - `tests/lattice.test.ts:36-48` creates a bare `AgentCert` in-memory and registers it directly, demonstrating the code path does not require a signed certificate package.
- Mitigation: Make registration require a signed certificate chain, validate the issuer signature against a trusted CA, and verify the agent signature over the mediated request payload.
- Suggested test: Attempt to register an altered certificate and assert registration fails when the CA signature or proof of possession is missing.

### F8. `P1` Delegation, intent, and capability constraints are mostly ignored during mediation

- Severity: `P1`
- Component: Authority enforcement
- Preconditions: A caller can reach `core/gateway.ts` with structurally valid objects.
- Abuse path: Reuse expired or over-broad delegation and capability objects, or change high-risk fields that the gateway never validates.
- Impact: Authority enforcement does not match the declared security model. Expirations, allowed actions, forbidden actions, approval flags, and amount constraints can be bypassed.
- Evidence:
  - `core/gateway.ts:161-168` only checks `capability.subject` and `capability.allowed_tool`.
  - `core/types.ts:65-103` and `core/types.ts:96-108` define richer delegation and capability constraints such as `expires_at`, `allowed_actions`, `forbidden_actions`, `max_amount`, and `requires_human_approval`.
  - `core/gateway.ts:85-98` only consults `WhitePolicy` when one is injected and a `capability_class` is provided.
- Mitigation: Validate signatures, expiry, intent/delegation scope, approval requirements, and monetary or customer constraints before any tool call is allowed.
- Suggested test: Submit an expired capability token and a delegation whose `allowed_actions` do not include the requested action; assert the gateway rejects both.

### F9. `P1` Revocation enforcement is inconsistent, name-based in the runtime, and does not require fresh proofs

- Severity: `P1`
- Component: Revocation model
- Preconditions: A cert, agent, or service becomes compromised after issuance.
- Abuse path: Continue using stale credentials or route through code paths that only consult the local name-based revocation list or a transient in-memory revocation network.
- Impact: Revocation behavior diverges across the runtime and SDK. Critical actions can proceed without fresh revocation evidence even though the whitepaper explicitly forbids that.
- Evidence:
  - `node/state.ts:103-116` stores revocations as plain agent names.
  - `node/entry.ts:24-27` blocks only on `isRevoked(agent)` string matches.
  - `core/gateway.ts:66-69` checks revocation only if a `RevocationNetwork` was injected and only against `hashObject(cert)`.
  - `node/ping.ts:41-43` reports `cert_status = valid` and `revocation = fresh` for any locally registered service without consulting revocation state.
  - `docs/lattice-whitepaper.md:766-768` states "For critical actions: no fresh revocation proof = no action."
- Mitigation: Unify revocation on certificate or key identifiers, require fresh revocation proofs on high-risk actions, and remove string-name revocation as a primary enforcement mechanism.
- Suggested test: Revoke a certificate after registration and assert every runtime path rejects it until a fresh non-revoked proof is presented.

### F10. `P1` SAAE generation uses placeholders and gateway-only signatures, so non-repudiation is not achieved

- Severity: `P1`
- Component: Signed Agent Action Envelope generation
- Preconditions: Operators rely on SAAE logs for audit or external proof.
- Abuse path: Invoke the gateway normally; it emits an envelope that contains placeholder hashes and a fake agent signature field.
- Impact: The stored envelope cannot prove what target was touched, what evidence bundle existed, or that the agent consented to the recorded action.
- Evidence:
  - `core/gateway.ts:134-139` uses placeholder values for `target_hash` and `bundle_hash`.
  - `core/gateway.ts:147-152` sets `agent_signature` to `PENDING_AGENT_SIG` and only signs with the gateway key.
  - `core/envelope.ts:22-30` creates the base envelope with an empty agent signature slot.
  - `README.md:50-60` claims request/response hashing and mathematically undeniable action provenance.
- Mitigation: Hash the actual target, request, response, and evidence bundle, require the agent signature before accepting the action, and persist the signed envelope as the audit primitive.
- Suggested test: Compare two envelopes produced for different request bodies and assert their target/evidence hashes differ and contain verifiable agent signatures.

### F11. `P1` The local action log is a mutable JSONL file with no integrity protection

- Severity: `P1`
- Component: Local transparency log
- Preconditions: A local user or compromised process can read and write under `~/.lattice`.
- Abuse path: Edit, truncate, or append `actions.jsonl` directly before batching or after an incident.
- Impact: Operators can no longer trust the local audit trail to reflect what actually happened, even before on-chain anchoring.
- Evidence:
  - `node/state.ts:127-140` appends and reads a plain JSONL file.
  - `cli/lattice.ts:220-242` tails that file directly and prints entries with no integrity checks.
  - `README.md:51-54` describes an immutable JSONL transparency log.
- Mitigation: Treat the signed SAAE or a signed append-only log record as the source of truth, add file integrity protection, and separate operator convenience views from the immutable audit artifact.
- Suggested test: Modify `actions.jsonl` between execution and `logs batch`, then assert the system detects tampering instead of silently using the edited file.

### F12. `P1` Batch creation and proof generation recompute Merkle leaves from mutable local state

- Severity: `P1`
- Component: Batch/proof generation
- Preconditions: An attacker can change local log lines or metadata before proof generation.
- Abuse path: Alter entries in `actions.jsonl`, then generate or verify a proof later. The code rebuilds leaves from the current file contents instead of a sealed batch artifact.
- Impact: Proofs can drift over time and may no longer correspond to the action data that was supposedly committed when the batch was created.
- Evidence:
  - `node/batch.ts:17-18` reads current log entries from `tailLog(10000)`.
  - `node/batch.ts:35-38` hashes the JSON string of the mutable log entries instead of a stored envelope hash.
  - `node/batch.ts:53` persists only batch metadata, not the sealed leaves or signed commitment package.
  - `node/batch.ts:74-89` reconstructs the proof from the current log file contents.
- Mitigation: Seal and persist the exact leaf set used to create a batch, sign the batch metadata locally, and generate proofs from the sealed batch artifact instead of the current live log.
- Suggested test: Batch an action, change a field in `actions.jsonl`, generate a proof, and assert the proof step fails because the batch contents no longer match the sealed artifact.

### F13. `P1` `LatticeLog` batch commitments and inclusion proofs can diverge after more entries are appended

- Severity: `P1`
- Component: In-memory log API
- Preconditions: The SDK log is used to compute a batch and later produce proofs after new entries have been added.
- Abuse path: Call `computeBatch()`, append new entries, then call `getProof()` for an older action.
- Impact: The returned proof root may refer to the entire current log, not the earlier committed batch, which breaks the expected linkage between a proof and a published commitment.
- Evidence:
  - `core/log.ts:134-151` computes a batch over only the slice of new entries since the previous batch.
  - `core/log.ts:156-168` later computes proofs over `this.entries` as a whole, not a specific batch slice.
- Mitigation: Associate every action with the batch that sealed it and generate proofs against that exact batch root.
- Suggested test: Append action A, compute batch 1, append action B, then request a proof for A and assert its root still matches batch 1.

### F14. `P2` Operator trust tooling reports certificate and revocation health without checking either

- Severity: `P2`
- Component: `lattice ping`
- Preconditions: An operator uses `ping` to decide whether a service is trustworthy.
- Abuse path: Register any service locally and run `lattice ping`; the tool reports `cert: valid` and `revocation: fresh` solely because the service exists in local state.
- Impact: Operational trust decisions can be based on false positives, especially during incident response or service onboarding.
- Evidence:
  - `node/ping.ts:36-43` sets `resolved = true`, `cert_status = valid`, and `revocation = fresh` for any locally registered service.
  - `cli/lattice.ts:246-272` presents that output as a "Trust-ping".
  - `cli/lattice.ts:117-123` allows local service registration with only a name and backend URL.
- Mitigation: Rename the current command to reflect that it is a local registry/health probe, or add real certificate and revocation validation before surfacing trust labels.
- Suggested test: Register a service with no certificate material and assert `ping` reports "unverified" rather than "valid/fresh".

### F15. `P2` Hardcoded localhost routing and raw private-key CLI arguments increase local compromise impact

- Severity: `P2`
- Component: Overlay routing and operational key handling
- Preconditions: A local adversary can bind ports first, inspect process arguments, or read shell history.
- Abuse path: Hijack the hardcoded relay/gateway ports or recover private keys passed through `--key` in shell history and process listings.
- Impact: Local compromise becomes a routing compromise, and on-chain credentials are exposed through operator UX rather than secure secret handling.
- Evidence:
  - `node/entry.ts:12-14` hardcodes the relay URL to `ws://127.0.0.1:8888`.
  - `node/relay.ts:12-17` hardcodes destination routing to localhost gateway ports.
  - `cli/lattice.ts:287-289` and `cli/lattice.ts:309-313` require raw private keys on the command line.
  - `node/chain.ts:21-39` consumes those keys directly to create wallets.
- Mitigation: Resolve relay and gateway targets from signed registry data, authenticate every hop, and switch CLI signing material to environment variables, key files, or an external signer.
- Suggested test: Attempt to start a rogue relay on the expected port before the legitimate process and assert the entry node refuses the connection without authenticating the relay identity.

## Validation notes

This review included lightweight, safe validation in addition to code inspection:

- `npm test` passed with 29 tests.
- `npm run build` completed successfully.
- A temporary `HOME` was used to run `lattice init` and `lattice agent create bot1`.
  - Observed `ca.json` contained only `caId`, `publicKey`, and `createdAt`.
  - Observed `bot1.json` contained only the public key and bare certificate fields, with no agent private key and no `ca_signature`.
- A direct `commander` parsing check showed `--no-internet` maps to `internet`, not `noInternet`.
- A temporary `EntryNode` instance returned `403 {"error":"Agent revoked"}` when called with `x-lattice-agent: spoofed-agent` and a matching revoked name, confirming that the user-supplied header is the effective identity source.

## Recommended next steps

1. Fix the `P0` items before positioning the runtime as a security boundary.
2. Convert identity, issuance, and envelope handling to signed artifacts instead of names and placeholders.
3. Rework the logging pipeline so proofs are generated from sealed, signed batch data rather than mutable JSONL state.
4. Reduce operator trust debt by correcting CLI/README claims that currently overstate enforcement.
