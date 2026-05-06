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
