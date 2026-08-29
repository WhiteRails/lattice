# Lattice Onion v1

`distributedMesh: true` now requires `overlayProtocol: onion-v1`. The process fails closed when the route is not v3, when fewer than three operator-diverse relays are available, when WSS or its registered SPKI pin fails, or when HPKE/onion authentication fails. There is no plaintext fallback in mesh mode.

## Security boundary

- Entry authenticates the local agent and encrypts the complete request to the Gateway with RFC 9180 HPKE: X25519/HKDF-SHA-256/AES-256-GCM.
- A circuit is exactly `guard → middle → exit`. Each WebSocket link has its own circuit ID and ntor-derived forward/backward keys.
- Relay traffic consists of binary WebSocket frames of exactly 16,384 bytes. AES-256-GCM authenticates version, direction, per-link circuit ID and sequence. A repeated/out-of-order sequence or invalid tag destroys the circuit.
- `CREATE2` initiators sign their link proof with their registered Ed25519 identity. The target's registered identity and onion key authenticate the ntor response.
- The exit sees the registered Gateway label and delivery endpoint plus an opaque HPKE envelope. It cannot read the agent, URL, headers, body or response.
- Every request carries a fresh response X25519 key. Gateway responses are HPKE-encrypted and additionally signed with the Gateway's registered Ed25519 identity.

Fixed cell sizes conceal application payload length within each fragment, but timing and cell counts remain observable. Onion v1 does not claim constant-rate cover traffic or post-quantum cryptography.

## Required configuration

```yaml
nodeId: entry-1
roles: [entry]
distributedMesh: true
overlayProtocol: onion-v1
crypto:
  backend: local # or plugin with pluginCommand
circuit:
  maxAgeSeconds: 600
  maxStreams: 100
  maxConcurrentStreams: 32
  guardLifetimeDays: 30
upstreamRelays:
  - label: relay-1
    url: wss://relay-1.example:8888
registry:
  chain:
    rpcUrl: https://chain.example
    contractAddress: "0x..."
tls:
  caFile: /etc/lattice/ca.pem # only needed for a private CA
```

The authenticated routing cache/directory must contain at least three active relay records with different `operatorId` values, Ed25519 identity keys, X25519 onion keys, WSS endpoints and TLS SPKI SHA-256 pins. The same three-relay exception is allowed only when explicitly enabled and every endpoint is loopback:

```yaml
circuit:
  allowSingleOperatorLoopbackTests: true
  allowInsecureLoopbackTests: true
```

Never enable those flags on a public node.

## Key operations

```bash
npm run lattice -- node keys init
npm run lattice -- node keys rotate --purpose onion
npm run lattice -- circuit status
```

Local keys are purpose-separated under `~/.lattice/keys/` (`0700` directory, `0600` files). A plugin backend receives bounded JSON operations and may keep private material inside an HSM/KMS. Rotation retains the retired local record for the configured overlap, while new handshakes use only the active key.

Compute a certificate SPKI pin:

```bash
openssl x509 -in /path/to/fullchain.pem -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -hex
```

Register a node only after its keys and TLS certificate exist:

```bash
npm run lattice -- node register \
  --label relay-1 --roles relay --operator operator-a \
  --tls-fingerprint-sha256 <64-hex-spki-pin> \
  --rpc <rpc> --contract <new-onion-v1-contract> --key-file /secure/operator.key
```

Onion v1 changes the `LatticeNode` contract record. Deploy a new contract and perform a blue/green rollout; do not point v1 nodes at a legacy deployment.

## Delivery modes

Public Gateway delivery uses the circuit exit to dial the registered, pinned Gateway WSS endpoint. Hidden delivery uses two independent three-hop circuits: Entry and the outbound-only Gateway select the descriptor's relay as their terminal rendezvous. The rendezvous brokers only the opaque HPKE request/response under a bounded token; Gateway poll/response operations are Ed25519-authenticated and replay-protected. It learns the registered Gateway label needed for authorization, but never receives a direct connection from the Gateway and therefore does not learn its real IP.
