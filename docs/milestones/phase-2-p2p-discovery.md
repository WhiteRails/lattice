# Fase 2 — P2P discovery (milestone)

Objetivo: un servicio puede cambiar de relay / IP sin re-anunciar on-chain en cada salto.

Prerequisito: Fase 1 estable (routing-cache + chain + WSS + ECDH mesh operativos).

Componentes planificados:

- Gossip ligero entre relays (`relay-presence`, TTL ~60s), firmado por nodos registrados on-chain.
- Anuncios cortos del gateway hacia relays (WebSocket persistente) con endpoints y `gatewayPubKey` + firma CA.
- `LpResolver`: chain → gossip cache vigente → `routing-cache.json` bootstrap.
- Health checks / expiración 2× TTL para marcar peers caídos.

Riesgos: sybil/flooding en gossip → aceptar solo mensajes firmados por `registerLatticeNode` activos.

No implementado en código hasta cerrar esta fase de diseño/implementación en un PR dedicado.
