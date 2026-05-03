# Lattice

**A Certified Overlay Network for Autonomous AI Agents**

Version: 0.1 Draft  
Status: Concept Whitepaper  
Date: May 2026

---

## Abstract

The internet was designed for humans, servers, applications, and open connectivity. It was not designed for autonomous artificial agents capable of planning, invoking tools, chaining APIs, acquiring resources, writing code, moving money, contacting people, deploying infrastructure, or accumulating operational power at machine speed.

Lattice proposes a new overlay network for AI agents.

It is structurally inspired by Tor-like networks: separate addressing, overlay routing, cryptographic service identity, and location-independent services. But Lattice has the opposite purpose.

> Tor protects anonymity.  
> Lattice protects accountable agency.

Lattice is not a "dark web for AI." It is a certified operational network where autonomous agents can communicate with services only through cryptographic identity, delegated capabilities, signed action envelopes, policy gates, privacy-preserving logs, and revocation.

The goal is not to make every AI thought visible. The goal is to prevent autonomous AI agents from turning intelligence into external operational power without identity, limits, traceability, and the ability to cut them off.

---

## 1. Core Thesis

The dangerous part of AI is not merely intelligence.

The dangerous part is:

```
intelligence + tools + credentials + scale + persistence + no accountability
```

Lattice exists to break that chain.

Current internet:

```
agent/script/app -> public API -> real-world effect
```

Lattice:

```
agent -> certified overlay -> gateway -> policy -> signed action -> audited effect
```

The central rule:

> No autonomous agent should perform high-impact digital actions unless it is certified, capability-limited, policy-checked, logged, and revocable.

---

## 2. Why a New Network?

White Protocol can exist over the normal internet. But long term, high-impact autonomous agents should operate through a separate network layer.

Why?

Because the normal internet cannot reliably distinguish:

- human
- bot
- script
- agent
- compromised session
- browser automation
- API client
- model-driven workflow

A separate overlay network gives us a cleaner boundary:

> If you are an AI agent performing autonomous actions, you enter through Lattice.

This allows services to enforce:

- No AgentCert, no access.
- No capability, no action.
- No policy approval, no execution.
- No signed envelope, no effect.
- No revocation check, no trust.

Lattice creates a new default:

> Autonomous action is not accepted as ordinary traffic.

---

## 3. Lattice vs Tor

Lattice borrows structural ideas from Tor-like systems, but reverses the purpose.

| Tor | Lattice |
|-----|----------|
| Hide user identity | Certify agent identity |
| Hide service location | Protect private payloads |
| Hide route | Hide unnecessary infrastructure details |
| Reduce traceability | Preserve operational accountability |
| Protect anonymity | Enable revocation & enforce capability limits |

The difference:

```
Tor:      "You cannot know who acted."
Lattice: "You can verify what certified agent acted,
           under whose authority,
           with what capability,
           while preserving private content."
```

Lattice may hide physical location.  
Lattice must **not** hide operational responsibility.

---

## 4. Design Principles

### 4.1 Certified Actors Only

Every node participating in Lattice must have a certificate.

Certificate types:

- `AgentCert`
- `HumanDelegationCert`
- `OrgCert`
- `ModelProviderCert`
- `ModelCert`
- `RuntimeCert`
- `GatewayCert`
- `ServiceCert`
- `RelayCert`
- `ToolCert`
- `AuditorCert`

No anonymous autonomous agents.

---

### 4.2 Private Transport, Accountable Action

Relays should not see private content.

But actions must still be attributable.

Lattice separates:

```
network privacy
```

from:

```
operational accountability
```

- A relay should not know the payload.
- A service gateway must know enough to enforce policy.
- An auditor may later verify the action through encrypted evidence.

---

### 4.3 Capability Before Connectivity

In normal networks, connectivity comes first.

In Lattice, capability comes first.

An agent cannot merely "connect" and then act. It must present:

1. `AgentCert`
2. `DelegationGrant`
3. `CapabilityToken`
4. `IntentAnchor`
5. `RevocationFreshnessProof`

Only then can it request action.

---

### 4.4 Revocation Is Native

Every important identity must be revocable:

- agent
- human delegation
- organization
- runtime
- relay
- gateway
- service
- tool
- model claim
- policy grant

A network for AI agents without revocation is useless.

---

### 4.5 Open Protocol, Federated Trust

Lattice must not be owned by one company.

Correct model:

- open specification
- multiple implementations
- federated trust registries
- multiple certificate authorities
- interoperable relays
- public test suites
- neutral governance

A company may build Lattice infrastructure.  
No company should own Lattice.

---

## 5. High-Level Architecture

```
[AI Agent Node]
      |
      | signed request
      v
[White Entry Node]
      |
      | encrypted overlay route
      v
[White Relay Network]
      |
      | private transport
      v
[White Service Gateway]
      |
      | identity + capability + policy
      v
[Certified Tool / API]
      |
      | signed external effect
      v
[Action Log + Evidence Store + Revocation Layer]
```

Lattice is composed of:

1. White Addressing
2. White Nodes
3. White Relays
4. Lattice Gateways
5. White Services
6. White Registry
7. White Certificate Authorities
8. White Revocation Network
9. White Action Logs
10. White Evidence Stores

---

## 6. White Addressing

Lattice services use cryptographic addresses.

Examples:

```
lp://github-gateway.ab72k.lattice
lp://stripe-proxy.91fa.lattice
lp://cloud-registry.00ac.lattice
lp://agent-market.331k.lattice
```

### 6.1 Stable subject vs rotatable keys (normative)

**A Lattice subject is not its signing key.** Every critical entity has a **stable subject identifier** (Traceveil DID / `did:traceveil:…` or a protocol-normalized `subject_id`). Signing, encryption, recovery, revocation, audit, and cold-root keys are **separate key records** with `key_id`, purpose, validity window, and lifecycle state. Rotating or revoking a key **does not** retire the subject.

The `.lattice` suffix in `lp://…` addresses is derived from a **stable binding** — the **subject id** (or a registered namespace id committed to that subject) — **not** from the current operational public key:

```
subject_id -> hash -> base32 -> .lattice suffix
```

Reference formula (reference implementations may use SHA-256 for the hash step):

```
lattice_suffix = base32(sha256(utf8(subject_id)))[0:32]
white_address  = lattice_suffix + ".lattice"
```

The registry publishes **which signing key** is active for that subject at a given time, overlapping windows during rotation, and transparency events (`KEY_ROTATION`, `EMERGENCY_KEY_COMPROMISE`, `FREEZE_SUBJECT`). Verifiers evaluate historical signatures against **key state at the action timestamp**, including compromise windows (see Trust Model: Stable Subject & Key Lifecycle).

### 6.2 Legacy note

Earlier drafts tied the suffix directly to `hash(public_key)`. That model is **deprecated**: it collapses identity and key material and prevents clean rotation. Implementations MUST migrate to subject-bound addressing.

---

## 7. Node Types

### 7.1 Agent Node

Runs an autonomous or semi-autonomous AI agent.

Must present:

- `AgentCert`
- `RuntimeCert`
- `DelegationGrant`
- `CapabilityToken`

An Agent Node may not directly access high-risk external services. It must go through a Lattice Gateway.

---

### 7.2 Entry Node

First Lattice node contacted by an agent.

Responsibilities:

- Verify node-level certificate
- Establish encrypted tunnel
- Check basic revocation status
- Route request into overlay
- Avoid seeing private payload when possible

---

### 7.3 Relay Node

Routes encrypted traffic.

Responsibilities:

- Participate in overlay routing
- Maintain `RelayCert`
- Respect routing protocol
- Avoid payload inspection
- Publish uptime/health proofs
- Accept revocation

Relays are accountable infrastructure participants, not anonymous volunteers.

---

### 7.4 Service Gateway

The most important node.

Responsibilities:

- Verify `AgentCert`
- Verify `DelegationGrant`
- Verify `CapabilityToken`
- Check revocation
- Classify risk
- Run policy engine
- Calculate Power Accumulation Score
- Request human approval if needed
- Execute tool call
- Produce Signed Agent Action Envelope
- Store encrypted evidence
- Publish log commitments

The gateway is the **actuator firewall**.

---

### 7.5 Service Node

A certified service exposed through Lattice.

Examples:

```
lp://gmail.lattice
lp://github.lattice
lp://stripe.lattice
lp://cloudflare.lattice
lp://gcp.lattice
lp://banking.lattice
```

In early versions, these may be proxies around existing APIs.

---

### 7.6 Registry Node

Resolves Lattice identities.

Answers:

- What is this `.lattice` address / name?
- What **stable subject** (`did:traceveil:…` / `subject_id`) does it name?
- What **signing key** (and other purposes) are registered, with which `key_id` and validity windows?
- Which signing key is **active** (and which are deprecated / retired / revoked)?
- What certificate chain does it use?
- Who issued it?
- Is the subject or a specific key **revoked**, **compromised**, or **frozen**?
- What capabilities does it accept?
- What gateways protect it?

---

### 7.7 Log Node

Stores tamper-evident commitments.

Does not need full private action data.

Stores:

- batch root
- timestamp
- issuer
- action count
- signature
- certificate refs
- revocation checkpoints

---

### 7.8 Witness Node

Watches logs and registries.

Purpose:

- Detect equivocation
- Detect log rewriting
- Detect hidden revocation manipulation
- Cross-sign checkpoints
- Increase public trust

---

## 8. Lattice Request Lifecycle

Example: an agent wants to draft and send an email.

### Step 1: Agent prepares request

```json
{
  "agent_id": "agent:acme:support-agent:v1",
  "intent": "reply_to_customer_ticket",
  "capability": "email:draft",
  "target_service": "lp://gmail-gateway.7fa2.lattice",
  "request_hash": "sha256:..."
}
```

The agent signs the request.

### Step 2: Entry Node verifies basic identity

Checks:

- Valid `AgentCert`
- Valid `RuntimeCert`
- Not revoked
- Valid timestamp
- Valid signature

### Step 3: Overlay routing

The request travels through Lattice.

Payload remains encrypted. Relays know only what they need to route.

### Step 4: Service Gateway evaluates action

Gateway checks:

- `AgentCert`
- `OrgCert`
- `HumanDelegationCert`
- `CapabilityToken`
- `IntentAnchor`
- Policy
- Revocation
- Power Accumulation Score
- Tool risk level

### Step 5: Policy decision

Possible decisions:

- `allow`
- `deny`
- `require_human_approval`
- `require_multisig`
- `rate_limit`
- `pause_agent`
- `revoke_capability`
- `escalate_to_auditor`

### Step 6: Action execution

If allowed, gateway executes the tool call.

Example:

```
gmail.draft_email  →  allowed (capability: email:draft)
gmail.send_email   →  blocked or requires approval (no send capability)
```

### Step 7: Signed Agent Action Envelope

Gateway emits an action envelope:

```json
{
  "schema": "lattice.action.v0.1",
  "action_id": "act_001",
  "timestamp": "2026-05-02T18:12:00Z",
  "agent": {
    "id": "agent:acme:support-agent:v1",
    "cert_hash": "sha256:..."
  },
  "authority": {
    "org": "org:acme",
    "delegation_hash": "sha256:...",
    "intent_hash": "sha256:..."
  },
  "service": {
    "address": "lp://gmail-gateway.7fa2.lattice",
    "service_cert_hash": "sha256:..."
  },
  "tool": {
    "name": "gmail.draft_email",
    "capability_class": "message:external:draft"
  },
  "policy": {
    "decision": "allow",
    "risk_level": 3
  },
  "evidence": {
    "request_hash": "sha256:...",
    "response_hash": "sha256:...",
    "encrypted_bundle_ref": "wp-evidence://acme/act_001"
  },
  "signatures": {
    "agent": "...",
    "gateway": "...",
    "tool": "..."
  }
}
```

### Step 8: Evidence storage

Sensitive data goes into encrypted evidence storage.

Not public.

### Step 9: Log commitment

Action envelope is added to an append-only log. Periodic Merkle root is published:

```json
{
  "batch_id": "batch_2026_05_02_18_00",
  "action_count": 500000,
  "merkle_root": "sha256:...",
  "signature": "..."
}
```

---

## 9. Capability Firewall

Lattice is not just a routing network.

It must include an enforcement layer: the **Capability Firewall**.

The firewall asks:

- What is this agent trying to do?
- Does it increase operational power?
- Is it reversible?
- Does it contact humans?
- Does it move money?
- Does it create infrastructure?
- Does it create credentials?
- Does it deploy code?
- Does it acquire compute?
- Does it increase social reach?
- Does it affect physical systems?

Capability classes:

| Class | Description |
|-------|-------------|
| `read:public` | Read publicly available data |
| `read:private` | Read private/restricted data |
| `write:private` | Write to private data store |
| `write:external` | Write to external system |
| `message:single` | Send a single message |
| `message:mass` | Send messages at scale |
| `money:draft` | Draft a payment |
| `money:execute` | Execute a payment |
| `code:generate` | Generate code |
| `code:execute` | Execute code |
| `code:deploy` | Deploy code to production |
| `credential:create` | Create new credentials/accounts |
| `cloud:provision` | Provision cloud infrastructure |
| `dns:modify` | Modify DNS records |
| `identity:create` | Create new identity |
| `legal:commit` | Commit to legal obligations |
| `physical:operate` | Operate physical systems |

The network's purpose is not only to connect.  
Its purpose is to **constrain action**.

---

## 10. Power Accumulation Score

Lattice tracks dangerous sequences.

A single action may look safe. A sequence may not.

Example sequence:

```
buy domain
rent GPU
deploy server
create email accounts
generate persuasive content
send mass messages
create payment account
hire freelancers
spawn more agents
```

Lattice assigns a **Power Accumulation Score (PAS)**.

PAS factors:

| Factor | Weight |
|--------|--------|
| `compute_acquired` | 10 |
| `money_accessible` | 5 |
| `credentials_created` | 20 |
| `infrastructure_modified` | 15 |
| `code_deployed` | 25 |
| `humans_contacted` | 10 |
| `reach_expanded` | 15 |
| `identity_multiplied` | 30 |
| `persistence_increased` | 20 |
| `agent_replication_attempted` | 50 |
| `sensitive_data_accessed` | 10 |

If PAS crosses thresholds:

- Pause agent
- Require human approval
- Require multisig
- Freeze capability
- Notify owner
- Notify service
- Trigger audit
- Publish elevated-risk commitment

This moves from:

> "Did this single action look allowed?"

to:

> "Is this agent accumulating operational power?"

---

## 11. Privacy Model

Lattice must not become a surveillance network.

**Public layer:**

- Hashes
- Signatures
- Certificate refs
- Batch roots
- Policy IDs
- Revocation status
- Timestamps

**Private layer:**

- Prompts
- Outputs
- Tool parameters
- Personal data
- Financial details
- Emails
- Documents
- Business secrets
- Reasoning traces, if stored

Rule:

> Public proof, private evidence.

Better:

> Traceable by design.  
> Private by default.  
> Revealable under due process.  
> Revocable always.

Evidence should be encrypted for:

- User
- Organization compliance
- Approved auditor
- Regulator when legally required
- Court process if applicable

No global plain-text log.  
No public dumping of prompts.  
No universal government database.

---

## 12. Revocation Network

Lattice needs fast revocation.

Revocation applies to:

- `AgentCert`
- `RelayCert`
- `GatewayCert`
- `ServiceCert`
- `CapabilityToken`
- `HumanDelegationCert`
- `RuntimeCert`
- `ModelCert`
- `ToolCert`

Example revocation record:

```json
{
  "schema": "lattice.revocation.v0.1",
  "target_type": "AgentCert",
  "target_hash": "sha256:...",
  "revoked_by": "org:acme",
  "reason": "policy_violation",
  "effective_at": "2026-05-02T19:00:00Z",
  "signature": "..."
}
```

High-risk services must check fresh revocation status.

> For critical actions: no fresh revocation proof = no action.

---

## 13. Logging at Scale

Do not put every action on a blockchain.

That does not scale.

Correct model:

```
action -> signed envelope
signed envelope -> append-only local/federated log
many envelopes -> Merkle tree
Merkle root -> transparency log
optional root -> external anchor
```

Blockchain can be used only as an optional notary, not as the database.

Lattice's scalable integrity layer:

- Hash chains
- Merkle batching
- Public/federated checkpoints
- Cross-log witnesses
- Selective audit proofs

---

## 14. Lattice Overlay Routing

Lattice can evolve in stages.

### v0: Simulated Network

- HTTPS
- mTLS
- Central/federated registry
- Gateway enforcement
- Signed action logs

Purpose: prove policy and action custody.

### v1: Real Overlay

- QUIC
- White addresses
- Certified nodes
- Service discovery
- Revocation-aware routing
- Gateway mediation

Purpose: separate agent traffic from normal web traffic.

### v2: Multi-Hop Routing

- Entry nodes
- Relay nodes
- Service nodes
- Encrypted circuits
- Witnessed logs
- Federated trust registries

Purpose: Tor-like network structure, without anonymous agent action.

### v3: Global Federation

- Multiple issuers
- Multiple trust registries
- National profiles
- Industry profiles
- Critical infrastructure profiles
- Cross-jurisdiction revocation
- Public conformance tests

---

## 15. Why Not Fork Tor?

Because Tor's design goal fights Lattice's design goal.

Tor is built for anonymity.  
Lattice is built for accountable autonomy.

Forking Tor would force the system to fight its own foundation.

**Take concepts:**

- Overlay network
- Self-authenticating addresses
- Service location privacy
- Multi-hop routing
- Cryptographic circuits

**Reject:**

- Anonymous autonomous action
- Unaccountable relays
- Anti-attribution defaults
- Lack of capability governance

**Build Lattice with modern primitives:**

- Rust or Go
- QUIC
- mTLS
- Ed25519
- BLAKE3/SHA-256
- Merkle trees
- Policy engine
- Certificate transparency
- Append-only logs

---

## 16. Enforcement Requirement

Lattice works only if important services enforce it.

A separate network is not enough.

Critical services must eventually say:

> If you are an autonomous agent, you cannot use ordinary credentials for high-impact actions. You must enter through Lattice.

Examples:

| Service | Requirement |
|---------|-------------|
| GitHub | Code merge by agent requires Lattice envelope |
| Stripe | Payment/invoice actions by agent require `AgentCert` |
| Cloudflare | DNS modification by agent requires capability grant |
| AWS/GCP | IAM and compute provisioning require runtime and agent identity |
| Gmail | Mass outbound agent email requires human approval and traceable envelope |
| Banks | Transfer execution requires high-assurance delegation |

Without enforcement, Lattice is optional.  
With enforcement, Lattice becomes an accountability layer.

---

## 17. Governance

Lattice must be open.

Required governance:

- Neutral foundation
- Open specification
- Public working groups
- Reference implementation
- Security audits
- Conformance suite
- Federated trust registry model
- No single root authority

**Bad model:**

- One company owns the CA
- One company controls all logs
- One company approves all agents
- One company stores all evidence

**Good model:**

- Protocol open
- Trust federated
- Evidence private
- Logs interoperable
- Issuers plural
- Governance transparent

---

## 18. MVP

Do not start by building global routing.

Start with the part that matters: **enforcement**.

### MVP Components

| Component | Description |
|-----------|-------------|
| `white-ca` | Certificate authority |
| `white-registry` | Identity registry |
| `white-gateway` | Policy enforcement gateway |
| `white-sdk` | Agent SDK |
| `white-log` | Append-only action log |
| `white-dashboard` | Audit dashboard |
| `white-policy` | Policy engine |

### MVP Demo

An AI agent tries to send an email.

| Case | Result |
|------|--------|
| No certificate | Blocked |
| Valid `AgentCert` but no capability | Blocked |
| Capability only for draft | Draft created |
| Agent tries to send | Human approval required |
| Human approves | Sent |
| Action completes | Signed envelope created, evidence encrypted, log committed |
| Agent revoked | Next request blocked |

This demo proves:

- Agent identity
- Delegation
- Capability limits
- Human approval
- Signed action custody
- Revocation
- Auditability

That is enough for v0.

---

## 19. Suggested Repository Structure

```
lattice/
  specs/
    lattice-addressing.md
    lattice-node-cert.md
    lattice-routing.md
    lattice-action-envelope.md
    lattice-revocation.md
    lattice-policy.md
  crates/
    white-ca/
    white-registry/
    white-gateway/
    white-sdk/
    white-log/
    white-policy/
    white-cli/
  examples/
    gmail-proxy/
    github-proxy/
    stripe-proxy/
    cloudflare-proxy/
  dashboard/
    web/
  testnet/
    docker-compose.yml
    local-ca/
    sample-agents/
    sample-services/
```

---

## 20. First Technical Milestone

Build **Lattice Local Testnet v0**.

It should include:

- 1 local CA
- 1 registry
- 1 gateway
- 1 fake agent
- 1 fake tool
- 1 log server
- 1 dashboard

Flow:

```
white-ca issue-org
white-ca issue-agent
white-ca issue-service
white-policy grant capability
white-agent call service
white-gateway enforce
white-log append
white-dashboard inspect
white-ca revoke-agent
white-agent call again -> blocked
```

---

## 21. Lattice and White Protocol

Important distinction:

| | |
|-|-|
| **White Protocol** | The standard for identity, delegation, signed actions, evidence, revocation. |
| **Lattice** | The overlay network where agents and certified services communicate using White Protocol. |

White Protocol can run without Lattice.  
Lattice cannot work without White Protocol.

---

## 22. Risk and Limitations

**Lattice does not solve:**

- AI alignment
- Superintelligence containment
- Human persuasion
- Local open-weight models
- Manual copy-paste of AI outputs
- Legacy APIs
- Non-adopting services
- Malicious governments
- Physical coercion

**Lattice does reduce:**

- Anonymous autonomous digital action
- Unbounded agent tool use
- Untraceable API operations
- Credential laundering
- Unaudited agent workflows
- Silent power accumulation
- Lack of revocation
- Lack of model/runtime/tool provenance

**Honest claim:**

> Lattice reduces the ability of AI agents to gain operational power through compliant digital systems without accountability.

That is strong enough. Do not overclaim.

---

## 23. One-Sentence Definition

> Lattice is a Tor-like overlay network for AI agents, but inverted: private in transport, accountable in action, restricted by capability, and revocable by design.

---

## 24. Short Pitch

The internet needs a separate trust layer for non-human actors.

Lattice gives AI agents their own certified network, where every meaningful action requires identity, delegated permission, policy enforcement, signed provenance, privacy-preserving audit, and revocation.

It is not a dark web.  
It is an **accountable web for autonomous intelligence**.

---

## 25. Final Position

The old internet asks:

> Can this client connect?

Lattice asks:

> Who is this agent?  
> Who authorized it?  
> What can it do?  
> Is this action allowed?  
> Is it accumulating power?  
> Can we audit it?  
> Can we stop it?

That is the difference.

Lattice is not about blocking intelligence.  
It is about governing agency.

The future risk is not that AI thinks.  
The risk is that AI acts with no boundary.

**Lattice is the boundary.**
