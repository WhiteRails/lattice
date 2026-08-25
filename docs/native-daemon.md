# Daemon C y clientes Rust

Lattice usa un daemon principal nativo (`latticed`) en C y clientes/SDKs en Rust. TypeScript conserva el CLI, el plano de control y las pruebas de referencia; no custodia claves de agentes ni implementa el protocolo local de firma. El cliente Rust ya despacha solicitudes concurrentes por un solo socket y las correlaciona por `request_id`.

## Contrato inicial: LTP/1

El primer límite de migración es IPC local por Unix socket. LTP/1 tiene un header binario fijo de 20 bytes:

| Bytes | Campo |
| --- | --- |
| 0–3 | `LTP1` |
| 4 | versión (`1`) |
| 5 | tipo de frame |
| 6–7 | flags reservados |
| 8–15 | `request_id` big-endian |
| 16–19 | tamaño del payload big-endian |

El límite estricto por frame es 1 MiB. El daemon opera con sockets no bloqueantes, `poll`, buffers con límites, presupuesto de 64 KiB de lectura y escritura por cliente/tick, una cola de salida de 2 MiB por cliente y un presupuesto agregado de buffers de 128 MiB (ajustable con `--max-buffered-bytes`, 4 MiB–1 GiB). El cliente Rust tiene un máximo de 4.096 solicitudes pendientes por conexión (configurable) y devuelve backpressure antes de acumular memoria. El daemon rechaza paths de socket existentes, no borra sockets de otros procesos y crea el suyo con permisos `0600`.

Un cierre de cliente durante una escritura se trata como fallo de ese cliente (`EPIPE`); nunca debe derribar el daemon mediante `SIGPIPE`.

`STATS` devuelve el protocolo, frames procesados, conexiones aceptadas, conexiones activas, rechazos por `--max-clients`, y uso/límite de buffer agregado. Es una señal local para autoscaling/alertas; no incluye datos de agentes ni secretos.

LTP/1 contiene control local (`PING` y `STATS`) y una ruta de firma opcional. Si el daemon recibe `--key-file` (Ed25519 PEM) y `--session-token-file`, el primer frame enviado a cada cliente es un desafío aleatorio. El cliente Rust responde con `HMAC-SHA256(token, challenge)` y sólo entonces puede usar `SIGN`; el token no viaja por LTP. Ambos archivos deben pertenecer al usuario del daemon y tener permisos `0600` o más restrictivos.

Esto migra la custodia de la clave de agente al proceso C. Todavía no transporta acciones de agentes ni tráfico overlay; por tanto no se debe confundir el socket local con una frontera de autorización remota.

## Compilar y probar

```bash
cmake -S daemon -B build/daemon
cmake --build build/daemon
cargo test --manifest-path clients/rust/Cargo.toml
npm run test:native
```

La integración nativa incluye 1.000 `PING` simultáneos por una única conexión
Unix: verifica multiplexación y correlación de LTP/1 sin usarlo como una
certificación de rendimiento ni de capacidad de producción.

Para medir una celda concreta sin abrir más sockets, el cliente Rust incluye
una carga multiplexada y emite JSON con solicitudes, concurrencia, tiempo y
RPS medido en esa máquina:

```bash
cargo run --manifest-path clients/rust/Cargo.toml -- --socket /tmp/latticed-demo.sock \
  load --requests 100000 --concurrency 1024 --payload-bytes 128
```

No compare esos resultados entre máquinas ni los extrapole directamente a la
capacidad global: son una señal de regresión local para dimensionar una celda.

El daemon requiere OpenSSL 3 para Ed25519 y HMAC. El build CMake lo resuelve como dependencia explícita. La provisión de clave y token abre archivos regulares privados mediante descriptor (`O_NOFOLLOW`), verifica propietario/permisos y no reabre la ruta validada.

Ejemplo de interoperabilidad:

```bash
build/daemon/latticed --socket /tmp/latticed-demo.sock &
cargo run --manifest-path clients/rust/Cargo.toml -- --socket /tmp/latticed-demo.sock ping hello
```

Para custodia nativa de una clave de agente, se crean los dos archivos con modo `0600`, se inicia el daemon con `--key-file` y `--session-token-file`, y el cliente Rust autentica el desafío antes de firmar:

```bash
build/daemon/latticed --socket /tmp/latticed-sign.sock --key-file /secure/bot1-ed25519.pem --session-token-file /secure/bot1-session.token &
cargo run --manifest-path clients/rust/Cargo.toml -- --socket /tmp/latticed-sign.sock --session-token-file /secure/bot1-session.token sign 'payload canónico'
```

El runner crea ese material por ejecución y arranca el daemon C para un agente Rust por defecto. La clave PEM efímera se elimina después de que el daemon la carga; el agente sólo recibe las rutas del socket y del token.

```bash
npm run build:native
npm run lattice -- run --agent bot1 -- cargo run --manifest-path clients/rust/Cargo.toml -- sign 'payload canónico'
```

El binario Rust `lattice` toma `LATTICE_SOCKET` o `LATTICE_DAEMON_SOCKET`, y `LATTICE_SESSION_TOKEN_FILE` para `sign`, cuando no se le pasan flags; el runner los inyecta sólo para la ejecución del agente.

Para Gateway/Entry replicados, configure `LATTICE_REPLAY_REDIS_URL` con un endpoint Redis o Valkey que soporte `SET NX PX`; `rediss://` exige TLS válido. El runtime usa una pool local de 16 conexiones (ajustable mediante `LATTICE_REPLAY_REDIS_POOL_SIZE`, 1–64), guarda sólo hashes de claves de replay, sigue redirecciones `MOVED` de Redis Cluster por slot y falla cerrado si el store no responde.

Para comprobar el adaptador contra un servidor local real (opcional, no forma parte de CI):

```bash
LATTICE_REDIS_INTEGRATION=1 LATTICE_REDIS_SERVER_BIN="$(command -v redis-server)" npm run test:replay-redis
```

## Migración del runtime

1. El daemon C absorbe lifecycle, IPC, límites, scheduling, pooling y métricas.
2. El cliente Rust absorbe firma local, streaming y SDK de agentes.
3. Entry, Relay y Gateway migran a transportes persistentes con multiplexación y cifrado extremo a extremo.
4. La política, revocación, rutas y auditoría dejan de depender de archivos síncronos en el camino de cada petición; el descubrimiento solicita nombres concretos, nunca tablas globales.

El protocolo externo deberá evolucionar a una especificación versionada separada de LTP/1, con handshake de identidad, capacidades delegadas, control de flujo, reintentos idempotentes y cifrado Entry–Gateway.
