# Example 2 — Bank: wire transfer with government-level validation

## Goal

The bank exposes a high-risk tool (`bank.transfer.wire`). Before the bank **gateway** accepts the bank agent’s call, the flow requires an **explicit approval document signed by the government CA** (amount, beneficiary, time window).

This models:

- **Separation of duties**: the bank does not “self-validate” sensitive transfers on internal policy alone; the government acts as a **second cryptographic authority**.
- **In production**: the same pattern fits SAAE compartments / co-signatures on `LatticeChain` (issuer registry, sealed evidence). Here it is an explicit `signData` / `verifySignature` step before `mediateToolCall`.

## Script flow

1. Government CA and bank CA (distinct issuers).
2. Trust stance: only the government public key is accepted for approvals of type `gov.transfer.approval.v1`.
3. Bank agent (certified by the bank) + `WhitePolicy` grant for `bank.transfer.wire`.
4. Without a government-signed approval → the gateway path is not taken (rejected earlier).
5. With a valid approval → `LatticeGateway.mediateToolCall` runs the gateway chain. With the current risk table (`money:execute` = 5), `WhitePolicy.evaluate()` **still** returns `require_human_approval` as the bank’s second barrier; that does not undo government validation, which happens **before** and is independent.
