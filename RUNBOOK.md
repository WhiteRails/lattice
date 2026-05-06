# Lattice Security Operations Runbook

**Version:** 1.0
**Project:** Lattice Security Hardening
**Compliance:** AC-21 (procedures 1–4 are required controls)

---

## Table of Contents

1. [AC-21-P1: Session Key Rotation](#ac-21-p1-session-key-rotation)
2. [AC-21-P2: Operator Key Compromise Response](#ac-21-p2-operator-key-compromise-response)
3. [AC-21-P3: Agent Revocation in Production](#ac-21-p3-agent-revocation-in-production)
4. [AC-21-P4: PAS State Rollback](#ac-21-p4-pas-state-rollback)
5. [KMS Plugin Development](#kms-plugin-development)
6. [Proxy Mode Network Limitation](#proxy-mode-network-limitation)
7. [Signing Socket Reference](#signing-socket-reference)
8. [F1 Distributed Public Overlay Bring-Up](#f1-distributed-public-overlay-bring-up)

---

## F1 Distributed Public Overlay Bring-Up

> **Scope.** F1 proves a real distributed public overlay: Entry on one VPS reaches a Gateway on another VPS through a public Relay over WSS, without sharing `overlaySecret`. F1 is **not** hidden-service mode: gateway endpoints are public route hints. Outbound-only hidden gateways/rendezvous are F3.

### Minimum topology

- Chain VPS: Anvil JSON-RPC reachable by operators, e.g. `http://chain.example:8545`.
- Relay VPS: `relay-1.example.com`, role `relay`, WSS `:8888`.
- Gateway VPS: `gw-echo.example.com`, role `gateway`, WSS `:8889`, backend on localhost.
- Entry VPS: `entry-1.example.com`, role `entry`, local HTTP proxy `127.0.0.1:7777`.

For 10 VPS, use the same pattern with 1 Anvil, 3 relays, 3 gateways, and 3 entry/agent nodes. Give every node a stable `nodeId` (`relay-1`, `gateway-echo`, `entry-1`, etc.).

### TLS / WSS

On every public Relay/Gateway VPS:

```bash
sudo certbot certonly --standalone -d relay-1.example.com
sudo certbot certonly --standalone -d gw-echo.example.com
```

Use the generated Let's Encrypt paths in `~/.lattice/node.yaml`:

```yaml
tls:
  certFile: /etc/letsencrypt/live/<domain>/fullchain.pem
  keyFile: /etc/letsencrypt/live/<domain>/privkey.pem
```

### Chain and namespace setup

On the Chain VPS:

```bash
anvil --host 0.0.0.0 --port 8545
npm run lattice -- chain deploy --rpc http://127.0.0.1:8545 --key-file /secure/operator.key
npm run lattice -- chain cert-type register lattice-node --level 1 --rpc http://127.0.0.1:8545 --contract <contract> --key-file /secure/operator.key
npm run lattice -- chain issuer register lattice-ops --type lattice-node --pub-key-hash 0x0000000000000000000000000000000000000000000000000000000000000000 --rpc http://127.0.0.1:8545 --contract <contract> --key-file /secure/operator.key
```

Register each node identity on-chain from that node after `lattice init`:

```bash
npm run lattice -- node register --label relay-1 --roles relay --rpc http://chain.example:8545 --contract <contract> --key-file /secure/operator.key
npm run lattice -- node register --label gateway-echo --roles gateway --rpc http://chain.example:8545 --contract <contract> --key-file /secure/operator.key
npm run lattice -- node register --label entry-1 --roles entry --rpc http://chain.example:8545 --contract <contract> --key-file /secure/operator.key
```

### Node configs

Relay:

```bash
npm run lattice -- node init --distributed-mesh --node-id relay-1 --roles relay \
  --relay-bind 0.0.0.0:8888 \
  --public-relay wss://relay-1.example.com:8888 \
  --chain-rpc http://chain.example:8545 --chain-contract <contract> \
  --tls-cert-file /etc/letsencrypt/live/relay-1.example.com/fullchain.pem \
  --tls-key-file /etc/letsencrypt/live/relay-1.example.com/privkey.pem
```

Gateway:

```bash
npm run lattice -- node init --distributed-mesh --node-id gateway-echo --roles gateway \
  --gateway-bind 0.0.0.0:8889 \
  --public-gateway wss://gw-echo.example.com:8889 \
  --chain-rpc http://chain.example:8545 --chain-contract <contract> \
  --tls-cert-file /etc/letsencrypt/live/gw-echo.example.com/fullchain.pem \
  --tls-key-file /etc/letsencrypt/live/gw-echo.example.com/privkey.pem
```

Entry:

```bash
npm run lattice -- node init --distributed-mesh --node-id entry-1 --roles entry \
  --entry-bind 127.0.0.1:7777 \
  --upstream-relays relay-1=wss://relay-1.example.com:8888 \
  --chain-rpc http://chain.example:8545 --chain-contract <contract>
```

### Service announce and route distribution

On the Gateway VPS:

```bash
npm run services:echo
npm run lattice -- gateway announce lp://echo.lattice \
  --backend http://127.0.0.1:9001 \
  --endpoint wss://gw-echo.example.com:8889 \
  --gateway-node-label gateway-echo
npm run lattice -- chain namespace register echo.lattice \
  --owner-issuer lattice-ops --public \
  --metadata-hash <metadataHash from gateway announce> \
  --rpc http://chain.example:8545 --contract <contract> --key-file /secure/operator.key
npm run lattice -- routing export --fqdn echo.lattice --out echo.route.json
```

Copy `echo.route.json` to every Relay that should route this service, then:

```bash
npm run lattice -- routing import --file echo.route.json --verify-chain --rpc http://chain.example:8545 --contract <contract>
```

### Start roles

```bash
# Relay VPS
npm run lattice -- node start --role relay

# Gateway VPS
npm run lattice -- node start --role gateway --service lp://echo.lattice --target http://127.0.0.1:9001

# Entry VPS
npm run lattice -- node start --role entry
```

### Acceptance smoke

On the Entry VPS:

```bash
npm run lattice -- agent create bot1
npm run lattice -- mesh smoke --agent bot1 --entry http://127.0.0.1:7777 --host echo.lattice --path /ping --expect-status 200
```

Expected: HTTP 200 with the backend response body, Relay/Gateway logs showing the request, and trace progression through `entry`, `relay`, `gateway`.

Negative checks:

- Change a node's on-chain pubkey or use an unregistered `nodeId`: peers must reject it with an unauthenticated/unregistered node error.
- Re-announce `echo.lattice` with a new Gateway endpoint, export/import the new route bundle, and confirm smoke recovers without changing Entry code.

---

## AC-21-P1: Session Key Rotation

> **Required AC-21 Control.** Rotate per-peer X25519 overlay session keys when a node key pair is suspected compromised, after a scheduled rotation window, or when a peer node is decommissioned.

### Background

Each node holds an X25519 key pair (`overlayNodeKeyPair`) stored in `~/.lattice/ca/ca.json`. On first contact with a peer, ECDH + HKDF-SHA256 derives a 32-byte session key cached for up to 1 hour (TTL). Rotating the node key pair forces all active sessions to rederive.

### Procedure

**Forced TTL expiry (no key material change):**

Session keys expire automatically after 1 hour. No operator action is required unless you need immediate expiry.

**Full key pair rotation:**

1. Stop the Lattice node to prevent new sessions from being established:
   ```
   lattice stop
   ```

2. Back up the current CA state before modifying it:
   ```
   cp ~/.lattice/ca/ca.json ~/.lattice/ca/ca.json.bak-$(date +%Y%m%d%H%M%S)
   ```

3. Open `~/.lattice/ca/ca.json` and remove the `overlayNodeKeyPair` field entirely (or set it to `null`). On next start, `getOrCreateOverlayKeyPair()` will generate a fresh X25519 key pair and persist it.

4. Restart the node:
   ```
   lattice start
   ```

5. Verify the new key pair was written:
   ```
   cat ~/.lattice/ca/ca.json | grep -c overlayNodeKeyPair
   ```
   Expected output: `1`

6. Notify all peer nodes of the key change so they discard cached session keys derived from the old public key. Peers will rederive on next contact.

7. Confirm sessions rederive in the action log:
   ```
   tail -f ~/.lattice/logs/actions.jsonl | grep session
   ```

**Rotating on all nodes in a cluster:**

Repeat steps 1–6 on each node sequentially. Stagger restarts to maintain quorum availability. All existing in-flight sessions will be dropped at the old TTL boundary (max 1 hour) even without explicit rotation.

---

## AC-21-P2: Operator Key Compromise Response

> **Required AC-21 Control.** Follow this procedure when the CA private key (`~/.lattice/ca/ca.json` `privateKey`) or any operator signing key is suspected or confirmed compromised.

### Detection Signals

- Unexpected entries in `~/.lattice/logs/actions.jsonl` signed by the operator key
- Alert from external audit/transparency log showing unexpected CA signatures
- Unauthorized access to the host running `~/.lattice/`

### Procedure

1. **Isolate immediately.** Take the affected node offline:
   ```
   lattice stop
   ```

2. **Preserve evidence.** Copy the full state directory before any changes:
   ```
   cp -r ~/.lattice/ ~/lattice-forensic-$(date +%Y%m%d%H%M%S)/
   ```

3. **Determine compromise window.** Review the action log for the earliest suspicious entry:
   ```
   cat ~/.lattice/logs/actions.jsonl | jq 'select(.decision == "allow")' | head -50
   ```

4. **Revoke the compromised CA certificate.** Publish a signed revocation record via the RevocationNetwork, specifying `reason_code`, `suspected_from`, and `confirmed_at` timestamps. Distribute this record to all peer nodes and transparency logs.

5. **Reinitialize CA state on the affected node:**
   ```
   mv ~/.lattice/ca/ca.json ~/.lattice/ca/ca.json.compromised
   lattice init
   ```
   This generates a new CA key pair and `overlaySecret`.

6. **Re-issue all agent certificates** signed by the compromised CA. For each agent:
   ```
   lattice agent revoke <agent-name>
   lattice agent issue <agent-name>
   ```

7. **Redistribute the new CA public key** to all peer nodes and service gateways that trusted the old CA.

8. **Rotate the overlay session key pair** following the procedure in AC-21-P1.

9. **Audit all actions taken during the compromise window** from `~/lattice-forensic-*/logs/actions.jsonl`. Report findings per your incident response policy.

10. **Bring the node back online** after confirming all downstream trusts have been updated:
    ```
    lattice start
    ```

---

## AC-21-P3: Agent Revocation in Production

> **Required AC-21 Control.** Revoke an agent when it is decommissioned, its key material is compromised, or its PAS score has triggered a forced pause.

### Revoke the agent

```
lattice revoke <agent-name>
```

This writes the agent name to `~/.lattice/revocations/list.json`.

### Verify revocation at the EntryNode

Check that the entry node's revocation list includes the agent:

```
cat ~/.lattice/revocations/list.json | jq '.[] | select(. == "<agent-name>")'
```

Expected: the agent name is printed. If the file is missing or the name is absent, the revocation did not persist — rerun `lattice revoke`.

### Verify revocation at the ServiceGateway

The ServiceGateway checks `isRevoked(agent)` on every inbound overlay message before policy evaluation. Confirm the gateway is reading the same `~/.lattice/revocations/list.json`:

1. Send a test request from the revoked agent (or simulate with a crafted overlay message).
2. The gateway must return HTTP 403 with body `{ "error": "AGENT_REVOKED" }`.
3. Confirm in the action log:
   ```
   tail -20 ~/.lattice/logs/actions.jsonl | jq 'select(.decision == "deny" and .reason == "AGENT_REVOKED")'
   ```

### Confirm blocked requests

A valid revocation produces this log pattern:

```json
{
  "timestamp": "...",
  "agent": "<agent-name>",
  "resource": "lp://<service>.lattice",
  "action": "...",
  "decision": "deny",
  "reason": "AGENT_REVOKED"
}
```

If you see `decision: allow` after revocation, verify both EntryNode and ServiceGateway share or sync the same `~/.lattice/revocations/list.json`. In multi-host deployments, replication of this file is the operator's responsibility.

### Remove the agent's signing socket (if running)

```
rm -f ~/.lattice/sockets/<agent-name>.sock
```

Stop any process holding the socket before removal to prevent stale file descriptor errors.

---

## AC-21-P4: PAS State Rollback

> **Required AC-21 Control.** Reset an agent's Power Accumulation Score when a false positive has triggered a pause, after a supervised agent rehabilitation period, or following a post-incident review that clears the agent.

### Background

PAS scores are persisted to `~/.lattice/pas-state.json` with per-entry HMAC-SHA256 integrity. The HMAC key is derived from the node's `overlaySecret` in `~/.lattice/ca/ca.json`. Any modification to `pas-state.json` that does not recompute the HMAC will cause that entry to be skipped with a `pas_tamper_detected` warning on next load.

### Procedure

**Option A: Remove a single agent's score**

1. Stop the Lattice node to prevent concurrent writes:
   ```
   lattice stop
   ```

2. Back up the current PAS state:
   ```
   cp ~/.lattice/pas-state.json ~/.lattice/pas-state.json.bak-$(date +%Y%m%d%H%M%S)
   ```

3. Retrieve the `overlaySecret` (HMAC key) from CA state:
   ```
   cat ~/.lattice/ca/ca.json | jq -r '.overlaySecret'
   ```

4. Remove the target agent's entry from the `scores` object in `pas-state.json`:
   ```
   cat ~/.lattice/pas-state.json | jq 'del(.scores["<agent-name>"])' > /tmp/pas-state-new.json
   mv /tmp/pas-state-new.json ~/.lattice/pas-state.json
   chmod 600 ~/.lattice/pas-state.json
   ```

   Because the entry is removed (not modified), no HMAC recomputation is needed. On next load, the agent will start from a zero score.

5. Restart the node:
   ```
   lattice start
   ```

6. Verify the agent's score is absent or reset to zero:
   ```
   cat ~/.lattice/pas-state.json | jq '.scores["<agent-name>"]'
   ```
   Expected: `null` (entry removed) or a fresh zero-score entry after first agent action.

**Option B: Full PAS state reset (all agents)**

1. Stop the node and back up the file as in Option A steps 1–2.
2. Replace the file with an empty state:
   ```
   echo '{"version":1,"scores":{}}' > ~/.lattice/pas-state.json
   chmod 600 ~/.lattice/pas-state.json
   ```
3. Restart the node.

**Editing existing entries (requires HMAC recomputation):**

If you need to adjust a score value rather than remove it, you must recompute the HMAC. The payload format is:

```
JSON.stringify({ agentId, score, factors })
```

Compute: `HMAC-SHA256(overlaySecret, payload)` and write the hex digest back to the `hmac` field for that entry. Entries with invalid HMACs are skipped on load and will emit a `pas_tamper_detected` warning.

---

## KMS Plugin Development

The `plugin` KMS backend delegates key retrieval and signing to an external process via stdin/stdout JSON. This enables integration with hardware security modules, vault services, or custom secret stores.

### Backend selection

Set the environment variable before starting the Lattice node:

```
LATTICE_KMS_BACKEND=plugin
LATTICE_KMS_PLUGIN_COMMAND=/path/to/your-kms-plugin
```

### Protocol

The Lattice daemon spawns the plugin command as a child process for each request. The daemon writes one JSON request to stdin, the plugin writes one JSON response to stdout, then both sides close.

**Request format:**

```json
{ "method": "getKey", "keyId": "<key-identifier>" }
```

```json
{ "method": "sign", "keyId": "<key-identifier>", "payload": "<data-to-sign>" }
```

**Response format (success):**

```json
{ "result": "<key-or-signature-string>" }
```

**Response format (error):**

```json
{ "error": "<human-readable error message>" }
```

The plugin must exit with code `0` on success. Any non-zero exit code is treated as a hard error.

### Minimal plugin example (Node.js)

```js
#!/usr/bin/env node
const chunks = [];
process.stdin.on('data', d => chunks.push(d));
process.stdin.on('end', () => {
  const req = JSON.parse(Buffer.concat(chunks).toString());
  if (req.method === 'getKey') {
    // Retrieve key from your store by req.keyId
    process.stdout.write(JSON.stringify({ result: '<base64-key>' }) + '\n');
  } else if (req.method === 'sign') {
    // Sign req.payload with the key identified by req.keyId
    process.stdout.write(JSON.stringify({ result: '<signature>' }) + '\n');
  } else {
    process.stdout.write(JSON.stringify({ error: 'unknown method' }) + '\n');
    process.exit(1);
  }
});
```

Make the plugin executable (`chmod +x`) and test it in isolation before wiring it into Lattice.

### Security notes

- The plugin process inherits the daemon's environment. Do not leak secrets via environment variables unless intentional.
- Plugin stderr is passed through to the daemon's stderr — suitable for diagnostic logging.
- There is no framing beyond newline separation; keep responses on a single line.

---

## Proxy Mode Network Limitation

**Advisory-only network controls in proxy mode.**

When running agents under proxy mode, network isolation controls are advisory only. The TUN-based network enforcement layer (WS8) has been deferred and is not implemented in this release. Proxy mode can log and report attempted out-of-policy network calls but cannot block them at the kernel or network level.

**Consequence:** A compromised or misbehaving agent running under proxy mode can make arbitrary outbound connections that bypass Lattice policy checks.

**Recommendation:** For workloads that require enforced network isolation, run agents in Docker mode. Docker mode uses container-level network namespacing to enforce `--network=none` or custom bridge policies, providing hard network boundaries that proxy mode cannot replicate.

```
lattice run --mode=docker <agent-name>
```

Do not rely on proxy mode as a security boundary for agents with access to sensitive services.

---

## Distributed overlay (cross-host MVP)

Operational pieces added for **Fase 1** (“distributed but not hidden”):

| Artifact | Purpose |
|---|---|
| `~/.lattice/node.yaml` | Binds (`entry`/`relay`/`gateway`), `upstreamRelays`, optional `registry.chain`, TLS files, `distributedMesh`. |
| `~/.lattice/routing-cache.json` | **HMAC-signed** local cache mapping `fqdn → { gatewayEndpoints, gatewayPubKeyB64 }` (must match chain `metadataHash` when namespaces are anchored). |
| `LATTICE_HOME` | **Override lattice state directory** from `~/.lattice` (tests/isolated VMs). |

### CLI recap

```
lattice node init-sample                 # scaffold node.yaml (edit before prod)
lattice node register …                  # governance: LatticeChain.registerLatticeNode
lattice routing announce …             # rewrite routing-cache row (+ optional --publish metadata)
lattice peer add …                     # bootstrap relay pubkey hints when chain unreachable
```

### Environment

- `LATTICE_CHAIN_RPC_URL` / `LATTICE_CHAIN_ADDRESS` — override YAML `registry.chain` for Entry/Relay resolvers.
- `LATTICE_DISTRIBUTED_MESH=1` — force ECDH mesh signing (same as `distributedMesh: true` in YAML).
- `LATTICE_PRIMARY_RELAY_LABEL` — label used to resolve relay overlay pubkey for Entry bootstrap.

### References

- Milestones: `docs/milestones/phase-*.md`
- Decisions: `docs/decisions-distributed-overlay.md`
- Example Anvil-only compose: `docker-compose.distributed.yml`

---

## Signing Socket Reference

### Overview

The signing socket allows an agent process to request cryptographic signatures from the Lattice daemon without ever holding the agent's private key. This limits key material exposure to the daemon process.

### Environment variables

| Variable | Description |
|---|---|
| `LATTICE_SIGNING_SOCKET` | Path to the Unix domain socket for the agent, e.g. `~/.lattice/sockets/<agent-name>.sock`. On Windows, this is a named pipe: `\\.\pipe\lattice-<agent-name>`. |
| `LATTICE_SESSION_TOKEN` | Per-session HMAC token. The agent uses this to authenticate to the socket by computing `HMAC-SHA256(LATTICE_SESSION_TOKEN, challenge)` in response to the daemon's challenge. |

Both variables are injected by the Lattice runner into the agent's environment at startup. Agents must not log or expose these values.

### Connection protocol

1. Agent connects to the socket at `LATTICE_SIGNING_SOCKET`.
2. Daemon sends a challenge: `{ "type": "challenge", "challenge": "<32-byte hex>" }`
3. Agent responds: `{ "type": "challenge_response", "response": "<HMAC-SHA256(LATTICE_SESSION_TOKEN, challenge) hex>" }`
4. Daemon confirms: `{ "type": "authenticated" }`
5. Agent sends sign requests: `{ "type": "sign", "payload": "<data>" }`
6. Daemon returns: `{ "type": "signature", "signature": "<signature>" }`

The socket enforces a rate limit of 100 sign requests per second per connection. Requests exceeding this limit receive `{ "type": "error", "error": "RATE_LIMITED" }`.

### Socket file permissions

The socket file is created with mode `0600`, owned by the user running the daemon. Only the daemon and agent processes running as the same user can connect. The socket directory (`~/.lattice/sockets/`) is created with mode `0700`.

### Using the socket instead of the private key

Agents should read `LATTICE_SIGNING_SOCKET` at startup. If the variable is set, all signing operations must go through the socket. Direct access to private key files from agent code is a policy violation and defeats the purpose of the signing socket isolation.
