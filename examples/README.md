# Examples

Runnable narratives on top of the Lattice MVP (`core/`).

| Path | Topic |
|------|--------|
| [01-government-citizen-certificate](./01-government-citizen-certificate/) | Who may issue “government” certificates; citizen binding (demo subject). |
| [02-bank-government-validated-transfer](./02-bank-government-validated-transfer/) | Bank transfer tool call gated by a separate government-signed approval. |
| [03-transparency-signed-manifest](./03-transparency-signed-manifest/) | Signed issuer manifest, Merkle log batch, on-chain checkpoint hook. |
| [testnet-demo.ts](./testnet-demo.ts) | End-to-end in-memory testnet (CA, registry, gateway, log, revoke). |
| [agents/node-agent.js](./agents/node-agent.js) | HTTP agent via Entry proxy (requires overlay stack). |

```bash
npm run example:gov
npm run example:bank
npm run example:manifest
npm run demo
```
