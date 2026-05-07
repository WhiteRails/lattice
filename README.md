# Lattice

**A certified overlay network for autonomous AI agents.**

<p align="center">
  <em>Don't give the agent the open internet. Give it Lattice.</em>
</p>Lattice is an overlay network infrastructure specifically designed to manage artificial intelligence agents in a secure and controlled manner. Unlike traditional networks, this system isolates agents from the open web through a Tor-inspired architecture that prioritizes accountability and privacy. The project utilizes cryptographic identities and restricted access policies to ensure that every action is verifiable and revocable. Additionally, it employs blockchain technology as a trust anchor to record the integrity of activities without compromising private data. This solution allows developers to deploy autonomous services under a framework of explicit permissions and constant monitoring. Its technical structure facilitates the creation of an environment where AI autonomy is limited by defined capabilities and immutable logs.

---

## How it works

```
Agent
  → Entry node (default-deny proxy)
    → Relay mesh (overlay routing)
      → Gateway (policy enforcement + SAAE log)
        → Real service
```

Agents never touch raw IP addresses or DNS. They request `lp://service.lattice` and Lattice resolves the cryptographic route, enforces capability policy, and records every action in a signed, tamper-evident log.

---

## Key Concepts

### Two addressing modes

| Address | Format | Trust anchor | Use case |
|---|---|---|---|
| `*.lattice` | human name | On-chain `LatticeChain` | Public/named services |
| `*.id` | `lp://<hex_pubkey>.id` | Pubkey embedded in address | Direct node-to-node |

`*.lattice` names are policy registries. The chain is the only authority — without it, a name can be hijacked. `*.id` addresses are self-authenticating: the pubkey *is* the identity, no lookup needed.

### Signed Agent Action Envelopes (SAAE)

Every action an agent takes through the network is recorded:

```json
{
  "agent_id": "...",
  "capability_used": "echo.ping",
  "request_hash": "0x...",
  "response_hash": "0x...",
  "gateway_signature": "...",
  "timestamp": "..."
}
```

Logs are JSONL, HMAC-signed, and periodically batched into Merkle trees. Only the root goes on-chain — prompts and payloads stay off-chain and private.

### Default-deny policy

Agents operate under YAML capability policies. If an agent tries to reach a resource it wasn't granted, the request is blocked at the Entry node before it leaves the machine.

---

## Requirements

- Node.js 20+
- Docker (recommended for network namespace isolation)
- For distributed deployment: VPS(s) + TLS (Let's Encrypt) + an EVM-compatible chain

## Installation

```bash
npm install
```

---

## Local quickstart (dev only)

Single-machine smoke test — entry + relay + gateway + echo service.

```bash
npm run lattice -- init
npm run lattice -- up --echo
```

Expected output:

```
[RelayNode]  Listening for overlay traffic on ws://127.0.0.1:8888
[Gateway]    lp://echo.lattice listening on ws://127.0.0.1:8889 -> http://127.0.0.1:9001
[Entry]      Listening for agent requests on http://127.0.0.1:7777
```

Create an agent, grant a capability, and run it:

```bash
npm run lattice -- agent create bot1
npm run lattice -- grant bot1 lp://echo.lattice echo.ping
npm run lattice -- run --agent bot1 -- node your_agent.js
```

Tail the live transparency log:

```bash
npm run lattice -- logs tail --follow
```

> **Note:** Local mode uses a shared `overlaySecret` and no chain. `*.lattice` names are not protected against hijacking in this mode. Use it for development only.

---

## Distributed deployment (canonical path)

**Goal:** an Entry on VPS-A reaches a Gateway on VPS-C through a public Relay on VPS-B over WSS, with `*.lattice` anchored on `LatticeChain`.

Full operational guide: `RUNBOOK.md` → "F1 Distributed Public Overlay Bring-Up".

### Minimum topology

- **Chain VPS** — EVM JSON-RPC (e.g. Anvil), accessible to operators
- **Relay VPS** — role `relay`, WSS `:8888`
- **Gateway VPS** — role `gateway`, WSS `:8889`, local HTTP backend
- **Entry VPS** — role `entry`, local HTTP proxy `127.0.0.1:7777`

### 1) TLS on Relay and Gateway

```bash
sudo certbot certonly --standalone -d relay-1.example.com
sudo certbot certonly --standalone -d gw-echo.example.com
```

`~/.lattice/node.yaml`:

```yaml
tls:
  certFile: /etc/letsencrypt/live/<domain>/fullchain.pem
  keyFile: /etc/letsencrypt/live/<domain>/privkey.pem
```

### 2) Deploy chain + register nodes

On the Chain VPS:

```bash
anvil --host 0.0.0.0 --port 8545
npm run lattice -- init
npm run lattice -- chain deploy --rpc http://127.0.0.1:8545 --key-file /secure/operator.key
```

On each VPS after `init`, register the node identity on-chain:

```bash
npm run lattice -- node register --label relay-1 --roles relay \
  --rpc http://chain.example:8545 --contract <contract> --key-file /secure/operator.key

npm run lattice -- node register --label gateway-echo --roles gateway \
  --rpc http://chain.example:8545 --contract <contract> --key-file /secure/operator.key

npm run lattice -- node register --label entry-1 --roles entry \
  --rpc http://chain.example:8545 --contract <contract> --key-file /secure/operator.key
```

### 3) Configure `node.yaml` per role

**Relay:**

```bash
npm run lattice -- node init --distributed-mesh --node-id relay-1 --roles relay \
  --relay-bind 0.0.0.0:8888 \
  --public-relay wss://relay-1.example.com:8888 \
  --chain-rpc http://chain.example:8545 --chain-contract <contract> \
  --tls-cert-file /etc/letsencrypt/live/relay-1.example.com/fullchain.pem \
  --tls-key-file /etc/letsencrypt/live/relay-1.example.com/privkey.pem
```

**Gateway:**

```bash
npm run lattice -- node init --distributed-mesh --node-id gateway-echo --roles gateway \
  --gateway-bind 0.0.0.0:8889 \
  --public-gateway wss://gw-echo.example.com:8889 \
  --chain-rpc http://chain.example:8545 --chain-contract <contract> \
  --tls-cert-file /etc/letsencrypt/live/gw-echo.example.com/fullchain.pem \
  --tls-key-file /etc/letsencrypt/live/gw-echo.example.com/privkey.pem
```

**Entry:**

```bash
npm run lattice -- node init --distributed-mesh --node-id entry-1 --roles entry \
  --entry-bind 127.0.0.1:7777 \
  --upstream-relays relay-1=wss://relay-1.example.com:8888 \
  --chain-rpc http://chain.example:8545 --chain-contract <contract>
```

### 4) Publish a service

On the Gateway VPS:

```bash
npm run services:echo
npm run lattice -- gateway announce lp://echo.lattice \
  --backend http://127.0.0.1:9001 \
  --endpoint wss://gw-echo.example.com:8889 \
  --gateway-node-label gateway-echo
```

This produces a `metadataHash` (routing commitment). Register the namespace on-chain:

```bash
npm run lattice -- chain namespace register echo.lattice \
  --owner-issuer lattice-ops --public \
  --metadata-hash <metadataHash> \
  --rpc http://chain.example:8545 --contract <contract> --key-file /secure/operator.key
```

Export the routing bundle and distribute it to relays:

```bash
npm run lattice -- routing export --fqdn echo.lattice --out echo.route.json
```

On each Relay:

```bash
npm run lattice -- routing import --file echo.route.json \
  --verify-chain --rpc http://chain.example:8545 --contract <contract>
```

### 5) Start all roles

```bash
# Relay VPS
npm run lattice -- node start --role relay

# Gateway VPS
npm run lattice -- node start --role gateway --service lp://echo.lattice --target http://127.0.0.1:9001

# Entry VPS
npm run lattice -- node start --role entry
```

### 6) End-to-end smoke test

From the Entry VPS:

```bash
npm run lattice -- agent create bot1
npm run lattice -- mesh smoke --agent bot1 \
  --entry http://127.0.0.1:7777 --host echo.lattice --path /ping --expect-status 200
```

---

## LatticeChain: public trust anchor

Lattice does not put agent actions or private prompts on a blockchain. It uses EVM-compatible chains only as a **public trust anchor** for namespace ownership and log integrity.

- SAAE logs are batched off-chain into Merkle trees
- Only the Merkle root is submitted to `LatticeChain.sol`
- Anyone can generate a zero-knowledge inclusion proof for a specific action without revealing the rest of the logs

```bash
# Create a batch
npm run lattice -- logs batch

# Anchor on-chain
npm run lattice -- checkpoint submit --batch <batch_id> \
  --rpc <RPC_URL> --key-file <key> --contract <ADDRESS>

# Verify an action
npm run lattice -- proof <action_id>
```

---

## Self-authenticating node identity (`*.id`)

Every Lattice node has a self-authenticating address derived from its overlay public key:

```bash
npm run lattice -- id
# Self-authenticating address:
#   lp:// URL : lp://deadbeef...cafebabe.id
#   fqdn      : deadbeef...cafebabe.id
#   pubkey    : <base64>
```

`*.id` addresses require no chain lookup. The pubkey is embedded in the address — at connection time, Lattice verifies the remote endpoint's pubkey matches the address. A poisoned federation entry with a different pubkey is rejected at resolution.

---

## Repository structure

```
cli/        CLI (npm run lattice -- ...)
contracts/  LatticeChain.sol
core/       Types, PKI, policy helpers
docs/       Architecture decisions and specs
node/       Entry / Relay / Gateway + resolver + routing-cache
services/   Example backends (echo, proxies)
tests/      Vitest
```

<details>
<summary><b>Useful commands</b></summary>

```bash
npm test

# Diagnostics
npm run lattice -- id
npm run lattice -- resolve lp://echo.lattice
npm run lattice -- logs tail --n 50

# Chain
npm run lattice -- chain namespace show echo.lattice --rpc <RPC> --contract <ADDR>

# Routing bundles
npm run lattice -- routing export --fqdn echo.lattice --out echo.route.json
npm run lattice -- routing import --file echo.route.json --verify-chain --rpc <RPC> --contract <ADDR>

# On-chain namespaces (owner-only slugs)
npm run lattice -- chain cert-type register AgentCert --level 1 --rpc <RPC> --key-file <key> --contract <ADDR>
npm run lattice -- chain issuer register lattice-ops --type operator --pub-key-file ./ops.pem --rpc <RPC> --key-file <key> --contract <ADDR>
npm run lattice -- chain reserved show governments --rpc <RPC> --contract <ADDR>
```

</details>

---

## License

MIT
