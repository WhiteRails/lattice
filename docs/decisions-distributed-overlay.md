# Decisiones — overlay distribuido

## LatticeChain

- Desarrollo local: JSON-RPC contra Anvil/Hardhat (`npm run lattice -- chain deploy …`).
- Testnet/L2 producción pendiente por operadores (Sepolia/Base/Arbitrum); el mismo ABI `LatticeChain.sol` aplica tras `npm run build:contracts`.

## TLS

- **Let’s Encrypt recomendado** en relays/gateways públicos: `tls: { certFile, keyFile }` en `~/.lattice/node.yaml` activa servidor HTTPS/WSS empotrado (`node/ws-stack.ts`).
- **Self-signed**: usar `tls.caFile` como pin en clientes outgoing (`wsTlsClientOptions`) más `tlsFingerprintSha256` on-chain opcional (`registerLatticeNode`).

## `overlaySecret` vs ECDH mesh

- Modo histórico (una sola máquina): HMAC fallback cuando `distributedMesh` es **false** (default sin YAML) y existe `LOCAL_FALLBACK_WS_REGISTRY`.
- **`distributedMesh: true`** en `node.yaml` o `LATTICE_DISTRIBUTED_MESH=1`: se exige ECDH conocido contra relay/gateway mediante `routing-cache` pubkey hints + registros chain (`registerLatticeNode`) + pubkey en mensajes overlay.

## Pruebas / estado aislado

- `LATTICE_HOME=<abs path>` redefine `~/.lattice` para suites y demos sin tocar el home del desarrollador (ver `tests/distributed.test.ts`).
