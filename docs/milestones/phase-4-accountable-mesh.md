# Fase 4 — Mesh auditable (milestone)

Objetivo: prueba verificable por salto sin publicar contenido privado.

Dirección:

- SAAE / firmas extendidas por hop (Entry witness, Relay witness además de agent + gateway).
- Revocations y issuer trust aplicados también desde eventos on-chain (subscriber en cada nodo).
- `lattice action verify …` usando Merkle en `LatticeLog` + raíz anclada (`submitCheckpoint`).

Reutiliza: `core/envelope.ts`, `core/log.ts`, `node/batch.ts`, `submitCheckpoint`.
