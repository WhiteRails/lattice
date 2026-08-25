# Arquitectura de escalabilidad de Lattice

Lattice no puede escalar a miles de millones como una malla global plana. La unidad de despliegue es una **celda**: un dominio administrativo/regional con Entries, Relays, Gateways, caché de política y un pipeline de auditoría. El plano global distribuye confianza y rutas firmadas; no transporta acciones ni guarda tablas completas de agentes.

```text
Agente Rust → latticed (C) → Entry regional → Relay regional → Gateway fleet → servicio
                         │                 │                 │
                         └─ firma local     └─ rutas por nombre └─ policy local
                                              con TTL/cache       + auditoría asíncrona
```

## Invariantes

- Cada flujo tiene límites explícitos de tamaño, concurrencia, timeout y cola; el loop C aplica presupuesto de I/O y de 64 frames por cliente y tick para preservar equidad, sin girar si sólo quedó un frame parcial.
- `latticed` también limita la suma de buffers de todos sus sockets (128 MiB por defecto), por lo que el límite de clientes no se traduce en memoria potencialmente ilimitada.
- Relay y Gateway admiten como máximo 4.096 operaciones overlay concurrentes por proceso y 128 por WebSocket, con 64 MiB globales y 8 MiB por peer retenidos; el contador de pesos por peer se actualiza en O(1), sin copias proporcionales al número de requests pendientes. Al saturarse cierran con `1013` para que el cliente reintente otra celda.
- Antes de admitir trabajo, cada Entry/Relay/Gateway/registry limita sockets entrantes a 8.192 por proceso, headers a 100 por request, headers incompletos a 15 s, requests HTTP a 60 s y WebSockets inactivos a 120 s. `LATTICE_MAX_INBOUND_CONNECTIONS`, `LATTICE_HTTP_HEADERS_TIMEOUT_MS`, `LATTICE_HTTP_REQUEST_TIMEOUT_MS` y `LATTICE_WEBSOCKET_IDLE_TIMEOUT_MS` permiten dimensionar esos presupuestos por celda sin dejar valores ilimitados. Las respuestas de discovery remoto están además limitadas a 64 KiB: una consulta de nombre no puede transformarse en una descarga de tabla.
- Entry reserva presupuesto antes de leer un cuerpo HTTP; limita el body a 512 KiB y los headers reenviados a 32 KiB para que la serialización Base64 no exceda el frame overlay de 1 MiB.
- Gateway aplica el mismo máximo de 512 KiB a respuestas de backend y 32 KiB a sus headers reenviados; corta un backend que no responde en 30 s (`LATTICE_BACKEND_RESPONSE_TIMEOUT_MS`, 1–120 s). Conserva la reserva de admisión hasta que el backend responde o falla y usa pools HTTP/HTTPS keep-alive acotados a 4.096 sockets (`LATTICE_BACKEND_MAX_SOCKETS`, 32–65.536), de modo que un backend lento no libera cupo prematuramente ni crea sockets ilimitados.
- Cada celda puede ajustar los contadores con `LATTICE_OVERLAY_MAX_INFLIGHT` (32–65.536) y `LATTICE_OVERLAY_MAX_INFLIGHT_PER_PEER` (1–8.192), y los bytes con `LATTICE_OVERLAY_MAX_INFLIGHT_BYTES` (1 MiB–1 GiB) y `LATTICE_OVERLAY_MAX_INFLIGHT_PER_PEER_BYTES` (1–64 MiB). Una configuración inválida falla al arrancar.
- Los pools salientes también se acotan por celda: `LATTICE_OVERLAY_RPC_MAX_CLIENTS` (32–8.192), `LATTICE_OVERLAY_RPC_MAX_PENDING` (32–65.536 global) y `LATTICE_OVERLAY_RPC_MAX_PENDING_PER_CONNECTION` (1–8.192). El total pendiente se mantiene con un contador O(1), no recorriendo los endpoints residentes por cada request. El exceso falla de inmediato en lugar de formar una cola.
- El cliente de esos pools aplica el mismo máximo LTP/overlay de 1 MiB a frames recibidos; una Gateway o Relay remota no puede elevar el límite con una configuración local permisiva.
- La caché de claves ECDH no crece con la cantidad total de nodos: guarda 8.192 peers por proceso por defecto, expulsa LRU tras limpiar TTL y se ajusta con `LATTICE_SESSION_MAX_ENTRIES` (32–65.536).
- Las políticas activas se mantienen en una caché LRU de 8.192 principales por Gateway (`LATTICE_POLICY_CACHE_MAX_ENTRIES`, 32–65.536); un watcher invalida el conjunto cuando cambia una policy y el miss vuelve a validar el archivo. La presencia o ausencia de una policy individual se cachea también durante un segundo, por lo que un agente portable no dispara `stat` por request. Cada archivo está limitado a 1 MiB, con hasta 256 reglas y 64 acciones por regla: el parseo y la evaluación permanecen con presupuesto fijo por solicitud. Los misses de policy son default-deny y su aviso se rate-limita sin incluir el principal no autenticado.
- El `PowerAccumulationTracker` opcional conserva como máximo 8.192 agentes por proceso; no expulsa un score para hacer sitio porque eso reduciría una decisión de riesgo. Una identidad nueva cuando el tracker está lleno falla cerrada. El estado PAS local se limita a 8 MiB y a la misma cardinalidad antes de parsearse; para poblaciones mayores debe particionarse o residir en un store de riesgo con semántica equivalente.
- Entry mantiene una caché LRU de identidad **pública** de agente (8.192 por defecto, `LATTICE_ENTRY_AGENT_CACHE_MAX_ENTRIES`, 32–65.536). No retiene claves privadas de agente; los archivos se limitan a 64 KiB y se revalidan como máximo una vez por segundo, con cache negativo para identidades ausentes.
- Para agentes remotos, Entry no requiere copiar una clave por identidad: el cliente adjunta su `SignedCert` en `x-lattice-agent-certificate` y Entry acepta sólo certificados vigentes emitidos por su propia CA o por una raíz incluida en `agentTrust.issuers` (máximo 64 externas por célula). La firma del agente se verifica antes de usar Relay; Gateway conserva la autorización fina por policy/issuer. Una raíz no configurada sigue recibiendo `401`.
- Entry y Gateway reutilizan como máximo 8.192 verificaciones de certificados de emisor por proceso (`LATTICE_ISSUER_CERTIFICATE_CACHE_MAX_ENTRIES`, 32–65.536), durante hasta 60 s y nunca más allá de `expires_at`. La caché no autoriza por sí sola: siempre se vuelve a aplicar el grant de servicio/acción o la policy individual.
- Gateway puede autorizar poblaciones emitidas por una raíz sin generar un YAML por agente mediante `gateway.issuerGrants`: cada grant permite un conjunto local de servicios/acciones y exige que el `AgentCert` traiga la capability exacta `lp://servicio.lattice:acción`. Una policy individual, si existe, prevalece y puede denegar; no se hacen wildcards de capability ni se acepta un certificado sólo por conocer su issuer.
- El bus local Gateway→runner que pausa agentes mantiene como máximo 8.192 procesos rastreados y 8.192 pausas pendientes, estas últimas sólo durante 60 s para cubrir la carrera de arranque. Al llenarse rechaza y termina el proceso recién creado antes de dejarlo sin control; no es una base de datos de policy distribuida.
- Redis/Valkey de replay usa una pool de conexiones, con 512 comandos pendientes por conexión y 5 s por comando por defecto. `LATTICE_REPLAY_REDIS_MAX_PENDING_PER_CONNECTION` (1–4.096) y `LATTICE_REPLAY_REDIS_COMMAND_TIMEOUT_MS` (100–10.000) hacen que un shard degradado falle cerrado, sin cola de promesas ilimitada.
- Si Redis Cluster responde `MOVED`, el cliente conserva como máximo 16 destinos de shard por proceso (`LATTICE_REPLAY_REDIS_MAX_CLUSTER_ENDPOINTS`, 1–64). Un control-plane de Redis erróneo no puede crear pools de sockets ilimitados.
- El parser RESP de replay conserva como máximo 64 KiB de una respuesta incompleta; la única operación permitida (`SET NX PX`) no requiere respuestas grandes, por lo que un servidor Redis corrupto no puede convertir bytes sin terminar en memoria ilimitada.
- Un relay no es autoridad de identidad ni de política.
- La consulta de una ruta no transfiere la tabla global de la federación.
- No se evicta un nonce aún válido: ante capacidad agotada se falla cerrado.
- Las revocaciones locales se cargan una vez por versión de archivo en un `Set` y se acotan a 100.000 principales por célula (`LATTICE_LOCAL_REVOCATION_MAX_ENTRIES`, 1.000–1.000.000). La versión se revalida como máximo cada segundo, no por request; un archivo corrupto o que excede ese presupuesto trata toda verificación como revocada. Las revocaciones globales deben llegar como deltas firmados por shard, no como un JSON monolítico en cada Entry.
- La `RevocationNetwork` de referencia aplica la misma regla de shard: 100.000 entradas por defecto, sin eviction de una revocación vigente; al llenarse el publicador debe reubicar el delta. Sus listados se limitan a 1.000 registros por llamada (máximo 10.000), nunca exponen un dump global, y el lookup compatible por hash es O(1).
- El `LatticeRegistry` de referencia también es un shard: 100.000 sujetos por defecto, 64 endpoints/issuers aceptados y 64 claves históricas por sujeto. Rechaza un nombre nuevo al llenarse, usa índices O(1) para sujeto y organización, y pagina nombres a 1.000 (máximo 10.000) en vez de listar la federación.
- `WhitePolicy` es un shard de control de 100.000 grants: resuelve `(agente, herramienta, capacidad)` mediante un índice O(1), caduca grants con un min-heap O(log n), no permite duplicados activos y pagina la vista administrativa. Una capacidad distinta no puede reutilizar una grant de la misma herramienta.
- El CA de referencia retiene como máximo 100.000 certificados para revocación local, y cada `LatticeGateway` de referencia admite 100.000 agentes distintos. Ambos rechazan capacidad nueva al llenarse; el gateway sí acepta una rotación del certificado de un agente ya registrado. En despliegues masivos se particionan por emisor y por `hash(agent_id)`.
- `LatticeLog` es un shard de transparencia de 100.000 entradas retenidas y 4.096 entradas sin sellar. Tiene cursor de lote O(1), búsqueda de acción O(1), localización de lote O(log b) e índice por agente. El plano de control debe exportar/rotar el segmento sellado antes de su capacidad; el nodo nunca descarta evidencia silenciosamente.
- `EvidenceStore` limita por defecto 100.000 bundles, 1 GiB cifrado retenido, 4 MiB por bundle y 64 destinatarios. No sobrescribe un `action_id`, y el re-cifrado reemplaza atómicamente su registro sólo si cabe en el presupuesto. El almacenamiento productivo debe implementar el mismo contrato sobre un object store/KMS particionado, no compartir memoria entre celdas.
- Las sesiones ECDH por peer usan un LRU con TTL de 8.192 entradas por defecto: consulta, renovación de uso y expulsión son O(1). No se escanea la tabla de peers cuando una celda alcanza su presupuesto de sesiones.
- Cada ruta de Gateway contiene como máximo 16 URLs `ws:`/`wss:` de hasta 2.048 bytes. Por eso Rendezvous Hashing y el failover del Relay son O(16) por request, no dependen del tamaño de la federación ni de una lista firmada malformada.
- El sellado local del journal consume un cursor durable y lotes de hasta 4.096 acciones o 16 MiB leídos por ejecución. No vuelve a leer acciones ni metadatos de lotes ya sellados en el camino normal; el escaneo de metadata sólo se usa para recuperación de un cursor perdido tras un corte.
- La operación administrativa `logs tail` lee como máximo 32 MiB y devuelve hasta 10.000 entradas JSONL. Si la ventana solicitada excede ese presupuesto, exige consultar el journal archivado en vez de cargar el historial completo de una celda.
- El mismo presupuesto de `routing-cache` se aplica a sus bootstrap nodes: por defecto 100.000 registros locales, renovables pero no expandibles al llenarse. Un cache firmado sobredimensionado se rechaza antes de hacerse residente.
- Un proceso retiene como máximo cuatro archivos de routing-cache parseados (LRU); cada nodo normalmente usa uno. Paths de prueba, migraciones o configuración dinámica no pueden multiplicar en memoria los artefactos de hasta 64 MiB.
- El registry de federation mantiene un min-heap indexado de expiraciones: renovaciones actualizan una sola fila y el sweep elimina sólo rutas vencidas, ambos O(log n). Ya no recorre todos los nombres al anunciar una ruta nueva ni acumula expiraciones antiguas de un nombre renovado.
- Las acciones no van a la blockchain; sólo compromisos Merkle agregados.
- Una clave de agente queda en el daemon/KMS, nunca en el proceso del agente.
- Un plugin KMS sólo puede devolver 64 KiB por invocación; resultados excesivos se terminan antes de acumularse en el proceso del Gateway/runner.
- Para rutas con réplicas públicas, todos los Relays usan Rendezvous Hashing de `(fqdn, agente)` para elegir la misma Gateway preferida sin una tabla de afinidad centralizada.
- Para una Gateway oculta, Relay mantiene un único multiplexor de respuestas por WebSocket y correlaciona por `request.id`; el número de pendientes no supera la admisión global de la celda y cada uno expira en 30 s. No se instala un listener EventEmitter por request ni se hace dispatch lineal por cada respuesta.
- Las rutas de federation se publican y consultan en sólo tres registries elegidos por Rendezvous Hashing de `fqdn`, no en toda la lista global; cada nombre tiene redundancia acotada y determinista. El resolver guarda hasta 10.000 rutas por célula, limita una ruta positiva a cinco minutos y cachea un miss durante cinco segundos para que un nombre inexistente no dispare fan-out repetido.
- `node.yaml` sólo contiene bootstrap/failover local: hasta 16 relays upstream, 16 rendezvous relays, 64 registries y 256 servicios por proceso. No se admite codificar una membresía global en la configuración de una célula.
- Gateway deriva `x-lattice-action-id` de la prueba firmada del agente. Los backends deben usarlo como clave de idempotencia para métodos no seguros cuando un failover pueda repetir una acción.

## Estado actual de la migración

| Área | Implementado | Próximo salto |
| --- | --- | --- |
| IPC y firma local | `latticed` C + LTP/1, HMAC por sesión y Ed25519 | KMS/HSM y múltiples identidades por daemon |
| Clientes | Rust con conexión multiplexada y backpressure: hasta 4.096 requests y 64 MiB de respuestas pendientes por conexión (techo 65.536/1 GiB), y cola de control de un frame | SDK async/streaming y soporte Windows |
| Transporte de referencia | Pool WebSocket persistente entre Entry, Relay y Gateway; afinidad de agente por Rendezvous Hashing | QUIC/HTTP3, streams, cancelación y E2E payload encryption |
| Descubrimiento | `GET /v1/routes/<fqdn>` firmado y caché TTL por resolver; el listado global público responde `410` | registros jerárquicos/gossip, deltas y almacenamiento durable |
| Identidad/policy/replay | pinning compatible e issuer+subject; caché de política; `ReplayStore` Redis/Valkey opcional con `SET NX PX` atómico, o memoria local para desarrollo | bundles compilados, issuer federation y revocación firmada distribuida |
| Auditoría | journal JSONL asíncrono con cola y retención local acotadas; Gateway falla cerrado si no puede registrar o retener la intención | shipper/cola duradera particionada y testigos cruzados |

## Reglas para cambios futuros

1. Ninguna API de hot path puede devolver una colección global de rutas, agentes o revocaciones.
2. Todo estado por identidad debe tener TTL, límite y mecanismo de invalidación o propagación.
3. Las rutas, políticas y revocaciones deben poder verificarse localmente desde una prueba firmada y cacheada.
4. La blockchain queda fuera del path de una solicitud; recibe raíces y cambios de autoridad por lote.
5. Una métrica de escala debe expresar identidad total, agentes concurrentes, requests/segundo y p99 por separado.
6. Una celda debe alertar sobre conexiones activas y rechazos por capacidad antes de aumentar el límite o añadir réplicas.
7. Entry o Gateway con más de una réplica deben configurar `LATTICE_REPLAY_REDIS_URL` (`redis://` o `rediss://`); si ese store no está disponible, las pruebas de agente fallan cerradas con `503`. Ambos comparten el store sólo dentro de su propia flota: los namespaces `entry:` y `gateway:` permiten que las dos verificaciones legítimas de la misma solicitud no se bloqueen entre sí.
8. La prueba local de varias dependencias está en `testnet/docker-compose.yml`: usa Redis efímero y publica Entry sólo en `127.0.0.1`. No contiene claves ni equivale a una celda de producción; use `rediss://`, credenciales y alta disponibilidad administrada entre réplicas reales.
9. Cada registry de federation es un shard de memoria acotada: por defecto admite 100.000 nombres vivos; `LATTICE_FEDERATION_MAX_ROUTES` permite 1.000–5.000.000. Al llenarse acepta renovaciones del mismo nombre, pero responde `503` a nombres nuevos para forzar redistribución, nunca crecimiento ilimitado.
10. El routing-cache local es un conjunto de rutas activas de una celda, no un espejo global: queda limitado a 100.000 nombres por defecto con `LATTICE_ROUTING_CACHE_MAX_ROUTES` (1.000–5.000.000) y 64 MiB serializados con `LATTICE_ROUTING_CACHE_MAX_FILE_BYTES` (1–512 MiB). Se firma localmente y su lectura hot-path reutiliza el contenido verificado sin hacer `stat` por solicitud. La versión del archivo se revalida como máximo cada segundo, que también es el límite de propagación de una eliminación local; un archivo excesivo se rechaza antes de `JSON.parse`.
11. La admisión a producción exige el [soak multi-celda](multicell-soak.md): replay entre réplicas, failover, degradación de Redis y partición de registry deben medirse con carga sostenida, no deducirse desde una sola máquina.
12. El journal de cada Gateway es un spool local de emergencia, no un archivo infinito: por defecto retiene hasta 1 GiB y falla cerrado al alcanzar el presupuesto. Configure `LATTICE_ACTION_JOURNAL_MAX_ENTRIES`, `LATTICE_ACTION_JOURNAL_MAX_QUEUE_BYTES`, `LATTICE_ACTION_JOURNAL_MAX_RETAINED_BYTES` y `LATTICE_ACTION_JOURNAL_FLUSH_MS`; un shipper externo debe archivar segmentos antes de agotar la retención.
13. Las lecturas de namespace y clave de nodo de `LatticeChain` se cachean por célula durante 30 s y hasta 10.000 claves (`LATTICE_CHAIN_CACHE_TTL_MS`, 1–300 s; `LATTICE_CHAIN_CACHE_MAX_ENTRIES`, 32–100.000). Un request no debe hacer RPC on-chain salvo en un miss acotado.
14. Cada Entry, Relay y Gateway **público** sirve `GET /healthz` y `GET /metrics` en su listener existente. Las métricas Prometheus tienen cardinalidad fija por `role` y reportan admisiones, bytes, rechazos, fallos agregados, límites y hits/misses/entradas de la caché de certificados, sin identidades ni rutas; úselas para dimensionar antes de subir un presupuesto. El hot path no escribe una línea de log por solicitud ni por failover: los fallos se cuentan en `lattice_overlay_failures_total`. Una Gateway oculta no abre listener por diseño y debe exportar las mismas métricas mediante su sidecar/agent local.

## Cobertura de réplica local

`tests/replica-contract.test.ts` ejecuta dos Entries que comparten el store de
replay, dos Gateways que comparten su namespace de acción y un Relay con un
endpoint preferido caído. La aserción es que sólo una réplica realiza la acción
y que el Relay llega a la réplica viva. También cubre 32 requests concurrentes
por un Gateway oculto registrado en Relay y verifica que el WebSocket conserva
el mismo número de listeners. Es una regresión de protocolo; el soak
externo sigue siendo necesario para validar latencia, quorum y red reales.
