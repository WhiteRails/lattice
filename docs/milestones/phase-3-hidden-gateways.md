# Fase 3 — Gateways ocultos / rendezvous (milestone)

Objetivo: el gateway **no expone puerto inbound** público identificable; el agente solo ve relays.

Ideas:

- Gateway mantiene conexiones **salientes** largas (`wss`) hacia relays fijos / mesh.
- Multiplexación de solicitudes tipo sub-stream (yamux/similar) sobre un solo WebSocket TLS.
- Relay hace rendezvous entre circuito entrante desde Entry y stream saliente hacia Gateway.
- NAT / CGNAT-friendly (solo egress desde el gateway).

Depende de Fase 1 + discovery (Fase 2) estable. Alto costo en ingeniería; no lanzar antes de tener operaciones y pruebas de carga sobre Fase 1.
