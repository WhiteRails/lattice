# Lattice
<img src="https://whiterails.com/ltt_concept.jpg">

**A Certified Overlay Network for Autonomous AI Agents.**

<p align="center">
  <em>Do not give the agent the open internet. Give it Lattice.</em>
</p>
---

The internet was designed for humans, open connectivity, and applications. It was **not** designed for autonomous AI agents capable of planning, invoking APIs, accumulating resources, and operating at machine speed. 

**Lattice** is an overlay network and cryptographic runtime that structurally isolates agents from the open web. It replaces implicit trust (API keys, loose firewalls) with explicit cryptographic identity, default-deny network routing, and undeniable cryptographic action provenance. 

It is structurally inspired by Tor-like networks: separate addressing (`lp://`), overlay routing, and cryptographic service identity. But it serves the opposite purpose: **where Tor protects anonymity, Lattice enforces accountable agency.**

---

## 🌟 Key Features

### 1. Two-Layer Architecture
Lattice is built as a complete ecosystem:
- **Protocol SDK (`src/`)**: A TypeScript library for building Lattice-compliant gateways, CAs, and registries.
- **Local Runtime (`daemon/`, `cmd/`)**: The `latticed` proxy and CLI tool that sit on the host machine to enforce policy at the network boundary.

### 2. Cryptographic Identity & Addressing (`lp://`)
Agents, humans, and services do not use IP addresses for trust. They use **Lattice Certificates**.
Services are registered under `lp://` addresses (e.g., `lp://github.lattice`), which mathematically bind the service location to a known cryptographic identity. 

### 3. `latticed` Default-Deny Proxy Firewall
The core of the local runtime. `latticed` intercepts all outbound HTTP/HTTPS traffic from your agent.
- **Agent Sandbox:** Agents are run in isolated environments (e.g., Docker with `--network none`) where their only exit node is `latticed`.
- **YAML Policies:** Agents operate under strict, human-readable YAML policies. If an agent tries to access `http://google.com`, the proxy blocks it. If it tries to `repo.delete` on `lp://github.lattice` without permission, the proxy blocks it.

### 4. Multi-Issuer Agent PKI (Traceveil Trust Chain)
Lattice implements a federated PKI architecture allowing multiple levels of certification for a single action:
- **User/Enterprise/Gov Certs**: Proves human identity or organizational authorization.
- **Model Provider Certs**: Certifies model provenance, config, and encrypted prompt evidence.
- **Agent & Tool Certs**: Cryptographically links the executing agent and the target API.

### 5. Post-Quantum Crypto-Agility
Lattice is built to withstand "harvest now, decrypt later" attacks. The protocol enforces algorithm agility via:
- Hybrid Handshakes: `X25519` + `ML-KEM-768`
- Hybrid Signatures: `Ed25519` + `ML-DSA-65`
- Hashing: `SHA3-512` for long-term Merkle Trees.

### 6. Federated Trust Registries
A decentralized system (`LatticeRegistry`) to resolve `lp://` names to cryptographic public keys, certificate issuers, and network locations, completely independent of global DNS.

### 5. Cryptographic Action Provenance (SAAE)
Every single action an agent takes through the network is recorded as a **Signed Agent Action Envelope (SAAE)**. 
- The proxy hashes the request and response.
- The action is appended to an immutable JSONL transparency log.
- This provides mathematically undeniable proof of *what* the agent did, *when*, and under *whose authority*.

### 6. LatticeChain: Public Trust Anchor
Lattice does **not** put agent actions or private prompts on a blockchain. However, to prevent silent log modification and to decentralize trust, Lattice uses EVM-compatible chains as a **Public Trust Anchor**.
- The runtime periodically batches off-chain SAAE logs into **Merkle Trees**.
- Only the **Merkle Root** is submitted to the `LatticeChain.sol` smart contract.
- Anyone can use the CLI to generate a zero-knowledge inclusion proof validating that a specific action existed at a specific time, without revealing the rest of the logs.

---

## 🚀 Getting Started

### Prerequisites
- Node.js v20+
- Docker (for sandbox isolation)

### Installation

```bash
git clone https://github.com/WhiteRails/lattice.git
cd LatticeNet
npm install
```

### 1. Initialize the Runtime
This generates your local Certificate Authority (CA) and creates the `~/.lattice/` state directory.
```bash
npm run lattice -- init
```

### 2. Create an Agent & Define Policy
```bash
# Issue a cryptographic certificate for your agent
npm run lattice -- agent create bot1

# Add a service to your local registry
npm run lattice -- service add echo --url http://127.0.0.1:9001

# Grant specific capabilities to the agent
npm run lattice -- grant bot1 lp://echo.lattice echo.ping
```

### 3. Start the Gateway Proxy
```bash
npm run lattice -- gateway start --port 7777
```

### 4. Run your Agent securely
This runs your agent with proxy environment variables injected. (Use `--docker` for true network namespace isolation).
```bash
npm run lattice -- run --agent bot1 --no-internet -- node your_agent.js
```

### 5. Audit the Actions
Tail the live transparency logs to see exactly what your agent is doing:
```bash
npm run lattice -- logs tail --follow
```

---

## 🔗 LatticeChain Verification (Phase 2)

Lattice includes a minimal Solidity smart contract (`contracts/LatticeChain.sol`) to anchor your logs publicly.

**Create a Merkle Batch:**
```bash
npm run lattice -- logs batch
> Created batch_d075dbe77157 with 42 actions.
> Merkle root: 0x41096fd...
```

**Anchor it on-chain (must use contract owner key):**
```bash
npm run lattice -- checkpoint submit --batch batch_d075dbe77157 --rpc <RPC_URL> --key-file <PATH_OUTSIDE_REPO> --contract <ADDRESS>
```

**Verify an action cryptographically:**
```bash
npm run lattice -- proof act_0f7b53976546
> Action: act_0f7b53976546
> Included in batch: batch_d075dbe77157
> Merkle root: 0x41096fd...
> Checkpoint: on-chain (verified)
```

**Namespaces (`*.lattice` on-chain):** Only ASCII lowercase `label.lattice` (single label, `[a-z0-9-]+`). Reserved official slugs (`governments`, `lattice`, `system`, `registry` by default) can **only** be registered by the **contract owner**. See [`docs/lattice-uri-scheme.md`](docs/lattice-uri-scheme.md) for the `lattice://` mapping and [`docs/Operator-key-security.md`](docs/Operator-key-security.md) for storing owner keys outside the repo.

```bash
npm run lattice -- chain cert-type register AgentCert --level 1 --rpc <RPC> --key-file ~/.secrets/lattice/owner.hex --contract <ADDR>
npm run lattice -- chain issuer register gov:ux:root --type government --pub-key-file ./gov-pub.pem --rpc <RPC> --key-file ~/.secrets/lattice/owner.hex --contract <ADDR>
npm run lattice -- chain issuer permit gov:ux:root AgentCert --rpc <RPC> --key-file ~/.secrets/lattice/owner.hex --contract <ADDR>
# Official governments host (owner key only):
npm run lattice -- chain namespace register governments.lattice --owner-issuer gov:ux:root --rpc <RPC> --key-file ~/.secrets/lattice/owner.hex --contract <ADDR>
# Public echo host (any wallet with gas):
npm run lattice -- chain namespace register echo.lattice --owner-issuer gov:ux:root --rpc <RPC> --key-file ~/.secrets/lattice/user.hex --contract <ADDR>

npm run lattice -- chain namespace hash governments.lattice
npm run lattice -- chain namespace show governments.lattice --rpc <RPC> --contract <ADDR>
npm run lattice -- chain reserved show governments --rpc <RPC> --contract <ADDR>
```

---

## 🛠 Project Structure

```text
├── src/                  # Layer 1: Protocol SDK (Types, Crypto, Gateways)
├── daemon/               # Layer 2: latticed Proxy, Policy Engine, State Manager
├── cmd/                  # Layer 2: `lattice` CLI framework
├── contracts/            # Layer 3: LatticeChain Trust Anchor (Solidity)
├── services/             # Mock lp:// services for local development
├── examples/             # Demo agents and API usage
└── testnet/              # Docker compose testnet bootstrap
```

## 📜 License
MIT
