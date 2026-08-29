# Soak multi-celda y failover

> **Runbook retirado.** Este procedimiento prueba el overlay HTTP/WebSocket
> anterior y no debe ejecutarse como validación de LNP/1. Use el runbook raíz y
> [`lnp-1.md`](lnp-1.md).

Este procedimiento valida propiedades distribuidas que no se pueden inferir de
un benchmark local. No convierte una medición en una cifra global: la capacidad
se publica por celda, región y perfil de payload.

## Topología mínima

- 2 Entries en hosts distintos, con agentes y rutas equivalentes.
- 2 Relays en la misma región/celda, cada uno con rutas firmadas para la misma
  Gateway fleet.
- 2+ réplicas de Gateway con una identidad de servicio registrada y policy
  idéntica; cada réplica conserva su propio journal.
- Redis o Valkey HA con TLS para `LATTICE_REPLAY_REDIS_URL`, accesible sólo
  desde las réplicas de Entry/Gateway.
- Tres registry shards para los nombres de la prueba; ningún nodo consulta una
  lista global.

Los endpoints configurados son conjuntos locales de arranque/failover (máximo
16 relays, 16 rendezvous y 64 registries por celda), no un inventario de todos
los nodos de la federación.

Configure los límites de la celda antes de empezar. Nunca incremente estos
valores durante el test para ocultar una cola:

```bash
export LATTICE_OVERLAY_MAX_INFLIGHT=4096
export LATTICE_OVERLAY_MAX_INFLIGHT_PER_PEER=128
export LATTICE_OVERLAY_MAX_INFLIGHT_BYTES=67108864
export LATTICE_OVERLAY_MAX_INFLIGHT_PER_PEER_BYTES=8388608
export LATTICE_OVERLAY_RPC_MAX_CLIENTS=1024
export LATTICE_OVERLAY_RPC_MAX_PENDING=8192
export LATTICE_MAX_INBOUND_CONNECTIONS=8192
export LATTICE_HTTP_HEADERS_TIMEOUT_MS=15000
export LATTICE_HTTP_REQUEST_TIMEOUT_MS=60000
export LATTICE_WEBSOCKET_IDLE_TIMEOUT_MS=120000
export LATTICE_BACKEND_RESPONSE_TIMEOUT_MS=30000
export LATTICE_BACKEND_MAX_SOCKETS=4096
export LATTICE_REPLAY_REDIS_MAX_CLUSTER_ENDPOINTS=16
export LATTICE_ACTION_JOURNAL_MAX_ENTRIES=10000
export LATTICE_ACTION_JOURNAL_MAX_QUEUE_BYTES=8388608
export LATTICE_ACTION_JOURNAL_MAX_RETAINED_BYTES=1073741824
export LATTICE_ACTION_JOURNAL_FLUSH_MS=5
export LATTICE_LOCAL_REVOCATION_MAX_ENTRIES=100000
export LATTICE_ENTRY_AGENT_CACHE_MAX_ENTRIES=8192
export LATTICE_CHAIN_CACHE_TTL_MS=30000
export LATTICE_CHAIN_CACHE_MAX_ENTRIES=10000
export LATTICE_SESSION_MAX_ENTRIES=8192
export LATTICE_POLICY_CACHE_MAX_ENTRIES=8192
export LATTICE_REPLAY_REDIS_URL='rediss://user:password@replay.example:6379/0'
```

## Fases

El cliente de carga incluido mantiene concurrencia y memoria constantes: firma
cada request con un nonce nuevo y conserva únicamente un histograma de
latencia de tamaño fijo. Ejecútelo desde una máquina que tenga la identidad
del agente, contra **cada** Entry de la célula. La salida JSON sirve para
persistir los cortes de la prueba sin etiquetas de agentes ni rutas:

```bash
# Rampa breve, detenida exactamente después de 50 000 solicitudes.
npm run lattice -- mesh load --agent soak-bot \
  --entry https://entry-a.cell.example --host echo.lattice \
  --duration-seconds 300 --concurrency 128 --max-requests 50000

# Soak completo. La memoria del generador no crece con las 24 horas.
npm run lattice -- mesh load --agent soak-bot \
  --entry https://entry-b.cell.example --host echo.lattice \
  --duration-seconds 86400 --concurrency 128 --report-interval-seconds 60
```

`2xx`, `4xx`, `5xx` y errores de transporte se reportan por clase; los
percentiles son el límite superior de buckets fijos. Correlacione esa salida
con `/metrics`, RSS, conexiones y los logs del journal para decidir si se
agregan réplicas. No use esta herramienta para aumentar límites de admisión.

1. **Baseline.** Compruebe una solicitud firmada por cada Entry y capture
   `STATS` de cada `latticed`, `GET /metrics` de Entry/Relay/Gateway, uso de CPU/memoria, p50/p95/p99 y rechazos
   `1013`/`503` por celda.
2. **Rampa.** Aumente concurrencia por agente gradualmente hasta que aparezca
   backpressure. El sistema debe rechazar, no formar una cola creciente; la
   memoria y pendientes deben estabilizarse.
3. **Soak.** Mantenga una carga representativa durante 24 horas. Registre RPS,
   p99, RSS, conexiones activas, rechazos, errores de Redis, latencia de
   journal, bytes retenidos/exportados por el shipper y rotación de rutas/policies.
4. **Replay entre réplicas.** Envíe exactamente el mismo `agent`, timestamp,
   nonce y firma a dos Entries. Debe haber una sola admisión y una sola acción
   backend; la otra respuesta debe ser `401 REPLAY_DETECTED`.
5. **Failover de Gateway.** Termine una Gateway preferida durante requests
   idempotentes. El Relay debe elegir el siguiente endpoint por Rendezvous y
   el backend debe deduplicar métodos no seguros con
   `x-lattice-action-id`.
6. **Degradación de Redis.** Corte el acceso al store durante 60 segundos.
   Entry/Gateway deben responder `503`, sin aceptar tráfico no verificable ni
   aumentar pendientes de Redis indefinidamente. Restablezca el store y mida
   recuperación sin reiniciar los roles.
7. **Partición de registry.** Aísle uno de los tres shards. Los nombres con
   cache/réplicas sanas deben seguir resolviendo; una ruta inexistente nunca
   debe inducir fan-out a todos los registries.

## Criterios de aceptación

- Memoria, pools, rutas, sessions y policies permanecen bajo sus presupuestos
  configurados durante toda la prueba.
- No hay duplicados de acciones, incluidos reintentos y failover.
- Ningún componente devuelve una tabla global de rutas/agentes/revocaciones.
- Redis degradado falla cerrado y su cola por conexión se mantiene bajo
  `LATTICE_REPLAY_REDIS_MAX_PENDING_PER_CONNECTION`.
- Las tasas de rechazo provocadas por capacidad son observables y llevan a
  agregar réplicas/celdas, no a elevar límites sin dimensionamiento.

La prueba local incluida en el repositorio cubre C/Rust, Redis real y roles
aislados. `tests/replica-contract.test.ts` además verifica en memoria el
contrato de dos Entries, dos Gateways y failover Relay→Gateway. Este documento
es la puerta de producción para validar el mismo contrato con fallos de red y
capacidad reales.

Con `LATTICE_REDIS_INTEGRATION=1`, `tests/redis-replay.integration.test.ts`
añade los contratos entre **dos procesos Entry** y entre **dos procesos
Gateway** con Redis real: el mismo request firmado sólo obtiene una admisión y
una acción backend. Es una prueba de integración reproducible, no un reemplazo
del soak multi-host.

La misma suite incluye dos Entries con directorios de estado independientes y
un certificado de agente portable firmado por un issuer configurado. Esto
comprueba que la réplica no necesita compartir archivos de agentes para que
Redis aplique la admisión única; el secreto HMAC de ese caso sigue siendo sólo
el modo local de pruebas, no una configuración multi-host.

También cubre dos Gateways con directorios, journals y grants de issuer
independientes: el mismo proof portátil llega a ambas réplicas, pero Redis deja
que una sola invoque el backend. Ninguno de estos contratos sustituye TLS,
identidad ECDH y redes separadas del soak multi-host.
