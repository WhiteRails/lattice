# lt: agente local limitado a Lattice

`lt` toma la forma de agente Unix compacto de [Vercel fx](https://github.com/vercel-labs/fx), revisado en el commit `fff3f63e348dec846bb235332974226bd2feae26` (Apache-2.0). No incorpora el runtime genérico de fx: sus herramientas de shell, filesystem, navegador, red remota y MCP exceden deliberadamente el alcance de Lattice.

El bundle de release contiene el binario Rust `lt`, `llama.cpp` como `lt-llm` (revisión `c1d0e7a004015f23bc0233470b747b596f29b264`) y SmolLM2-135M-Instruct Q4_K_M (105,454,432 bytes, Apache-2.0). El script fija y verifica el commit de `llama.cpp` y el SHA-256 del modelo antes de empaquetar. `lt` ejecuta sólo ese binario hermano con sólo ese modelo hermano; no acepta endpoint, servidor, URL ni ruta de modelo proporcionados por el usuario.

## CLI nativa completa

`lt` reexpone como comandos explícitos todos los comandos del binario nativo `lattice`, conservando sus argumentos y su código de salida:

- `lt [--socket <path>] status` (incluye el alias `stats`)
- `lt [--socket <path>] ping [payload]`
- `lt [--socket <path>] --session-token-file <path> sign <payload>`
- `lt [--socket <path>] load [--requests <n>] [--concurrency <n>] [--payload-bytes <n>]`

Esos comandos son solicitudes directas del operador y se ejecutan sólo contra el binario `lattice` hermano del bundle, sin shell ni resolución por `PATH`. En cambio, `lt ask <prompt>` y el modo interactivo usan el modelo local.

## Frontera del harness

El modelo recibe un contrato JSON y sólo puede proponer:

- `lattice_status`: lee los contadores LTP/1 del socket de daemon configurado.
- `lattice_ping`: verifica conectividad LTP/1 con un payload máximo de 1 KiB.

El proceso host restringe la generación con un esquema JSON y valida cada respuesta antes de tocar Lattice. Rechaza herramientas desconocidas, argumentos extra, payloads grandes, respuestas malformadas y cualquier acción sin `--socket`, `LATTICE_SOCKET` o `LATTICE_DAEMON_SOCKET`. Después de una única acción permitida, el host devuelve el resultado directamente: no deja al modelo encadenar llamadas.

No hay herramienta para ejecutar comandos, acceder a archivos, abrir red externa, cargar servidores MCP, iniciar daemon, cambiar la configuración, crear agentes, modificar políticas, leer claves ni firmar. El daemon C conserva la custodia de claves; `lt` no expone `SIGN` aunque el socket tenga firma habilitada.

Cada acción aceptada se anuncia por stderr como una línea de auditoría `lt audit`. La salida estándar contiene únicamente la respuesta final para facilitar automatización.
