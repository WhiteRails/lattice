# WhiteNet

**A Certified Overlay Network for Autonomous AI Agents.**

<p align="center">
  <em>Do not give the agent the open internet. Give it WhiteNet.</em>
</p>

---

The internet was designed for humans, open connectivity, and applications. It was **not** designed for autonomous AI agents capable of planning, invoking APIs, accumulating resources, and operating at machine speed. 

**WhiteNet** is an overlay network and cryptographic runtime that structurally isolates agents from the open web. It replaces implicit trust (API keys, loose firewalls) with explicit cryptographic identity, default-deny network routing, and undeniable cryptographic action provenance. 

It is structurally inspired by Tor-like networks: separate addressing (`wp://`), overlay routing, and cryptographic service identity. But it serves the opposite purpose: **where Tor protects anonymity, WhiteNet enforces accountable agency.**

---

## 🌟 Key Features

### 1. Two-Layer Architecture
WhiteNet is built as a complete ecosystem:
- **Protocol SDK (`src/`)**: A TypeScript library for building WhiteNet-compliant gateways, CAs, and registries.
- **Local Runtime (`daemon/`, `cmd/`)**: The `whitenetd` proxy and CLI tool that sit on the host machine to enforce policy at the network boundary.

### 2. Cryptographic Identity & Addressing (`wp://`)
Agents, humans, and services do not use IP addresses for trust. They use **WhiteNet Certificates**.
Services are registered under `wp://` addresses (e.g., `wp://github.white`), which mathematically bind the service location to a known cryptographic identity. 

### 3. `whitenetd` Default-Deny Proxy Firewall
The core of the local runtime. `whitenetd` intercepts all outbound HTTP/HTTPS traffic from your agent.
- **Agent Sandbox:** Agents are run in isolated environments (e.g., Docker with `--network none`) where their only exit node is `whitenetd`.
- **YAML Policies:** Agents operate under strict, human-readable YAML policies. If an agent tries to access `http://google.com`, the proxy blocks it. If it tries to `repo.delete` on `wp://github.white` without permission, the proxy blocks it.

### 4. Federated Trust Registries
A decentralized system (`WhiteRegistry`) to resolve `wp://` names to cryptographic public keys, certificate issuers, and network locations, completely independent of global DNS.

### 5. Cryptographic Action Provenance (SAAE)
Every single action an agent takes through the network is recorded as a **Signed Agent Action Envelope (SAAE)**. 
- The proxy hashes the request and response.
- The action is appended to an immutable JSONL transparency log.
- This provides mathematically undeniable proof of *what* the agent did, *when*, and under *whose authority*.

### 6. WhiteChain: Public Trust Anchor
WhiteNet does **not** put agent actions or private prompts on a blockchain. However, to prevent silent log modification and to decentralize trust, WhiteNet uses EVM-compatible chains as a **Public Trust Anchor**.
- The runtime periodically batches off-chain SAAE logs into **Merkle Trees**.
- Only the **Merkle Root** is submitted to the `WhiteChain.sol` smart contract.
- Anyone can use the CLI to generate a zero-knowledge inclusion proof validating that a specific action existed at a specific time, without revealing the rest of the logs.

---

## 🚀 Getting Started

### Prerequisites
- Node.js v20+
- Docker (for sandbox isolation)

### Installation

```bash
git clone https://github.com/WhiteRails/AgneticProtocol.git
cd AgneticProtocol
npm install
```

### 1. Initialize the Runtime
This generates your local Certificate Authority (CA) and creates the `~/.whitenet/` state directory.
```bash
npm run whitenet -- init
```

### 2. Create an Agent & Define Policy
```bash
# Issue a cryptographic certificate for your agent
npm run whitenet -- agent create bot1

# Add a service to your local registry
npm run whitenet -- service add echo --url http://127.0.0.1:9001

# Grant specific capabilities to the agent
npm run whitenet -- grant bot1 wp://echo.white echo.ping
```

### 3. Start the Gateway Proxy
```bash
npm run whitenet -- gateway start --port 7777
```

### 4. Run your Agent securely
This runs your agent with proxy environment variables injected. (Use `--docker` for true network namespace isolation).
```bash
npm run whitenet -- run --agent bot1 --no-internet -- node your_agent.js
```

### 5. Audit the Actions
Tail the live transparency logs to see exactly what your agent is doing:
```bash
npm run whitenet -- logs tail --follow
```

---

## 🔗 WhiteChain Verification (Phase 2)

WhiteNet includes a minimal Solidity smart contract (`contracts/WhiteChain.sol`) to anchor your logs publicly.

**Create a Merkle Batch:**
```bash
npm run whitenet -- logs batch
> Created batch_d075dbe77157 with 42 actions.
> Merkle root: 0x41096fd...
```

**Anchor it on-chain:**
```bash
npm run whitenet -- checkpoint submit --batch batch_d075dbe77157 --rpc <RPC_URL> --key <PRIVATE_KEY> --contract <ADDRESS>
```

**Verify an action cryptographically:**
```bash
npm run whitenet -- proof act_0f7b53976546
> Action: act_0f7b53976546
> Included in batch: batch_d075dbe77157
> Merkle root: 0x41096fd...
> Checkpoint: on-chain (verified)
```

---

## 🛠 Project Structure

```text
├── src/                  # Layer 1: Protocol SDK (Types, Crypto, Gateways)
├── daemon/               # Layer 2: whitenetd Proxy, Policy Engine, State Manager
├── cmd/                  # Layer 2: `whitenet` CLI framework
├── contracts/            # Layer 3: WhiteChain Trust Anchor (Solidity)
├── services/             # Mock wp:// services for local development
├── examples/             # Demo agents and API usage
└── testnet/              # Docker compose testnet bootstrap
```

## 📜 License
MIT
