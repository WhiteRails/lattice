# Lattice Network Protocol

<p align="center">
  <img src="docs/assets/lattice.svg" alt="Logo de Lattice" width="180" />
</p>

Lattice es una red privada administrada para conectar agentes, personas y
servicios sin exponerlos directamente a Internet. La aplicación sigue usando
TCP, UDP o ICMP normalmente; `lattice-netd` captura esos paquetes en una
interfaz virtual y los lleva por **LNP/1**, un túnel QUIC con TLS 1.3, mTLS,
rutas firmadas y políticas L3/L4.

```text
tu aplicación → interfaz Lattice (TUN) → QUIC/mTLS → Gateway → servicio privado
```

La primera distribución instalable es Linux. Los adaptadores macOS y Windows
están en el repositorio para compilación y pruebas, pero requieren firma,
notarización y permisos propios de cada plataforma antes de distribuirse.

## Empieza en cinco minutos

### 1. Prueba el código sin tocar tu red

Necesitas Rust 1.88+, Node.js 20+ y, para el daemon nativo, CMake/OpenSSL.

```bash
git clone <URL-del-repositorio>
cd AgneticProtocol
npm install
npm run build:network
npm run test:network
```

Esto compila `lattice-netd`, `lattice-gatewayd`, `lattice-resolver` y
`lattice-netctl`, y ejecuta las pruebas del workspace. Todavía no crea una
VPN: para eso hacen falta un perfil firmado, permisos de TUN y un Gateway.

### 2. Instala el cliente Linux

Descarga un release bundle de Lattice, descomprímelo y ejecuta como root:

```bash
sudo ./install-network.sh
```

El instalador coloca los binarios, unidades systemd, el handler de URI
`lttc://`, reglas de forwarding y los directorios protegidos de perfiles. No
instala una identidad automáticamente: la clave privada se genera en el
almacén del sistema durante el enrolamiento.

### 3. Enrola un perfil

Un operador debe entregarte un `profile.offer.json` firmado. El bundle contiene
la raíz TLS privada, el pin del Gateway, rutas/políticas iniciales y un token
de un solo uso; **nunca** contiene una clave privada.

```bash
export LATTICE_CONTROL_PUBLIC_KEY_B64='<clave-publica-de-control-pinneada>'
sudo -E lattice profile enroll /secure/profile.offer.json
sudo lattice profile status
```

Si necesitas el UUID para los comandos siguientes, léelo del offer (no lo
inventes):

```bash
jq -r '.payload.profile_template.profile_id' /secure/profile.offer.json
```

El comando crea la clave local, envía un CSR con pinning y guarda el perfil en
`/var/lib/lattice/profiles/<uuid>` con permisos restrictivos. Certificados y
leases son breves; si el estado firmado queda vencido durante 24 horas, el
túnel se cierra (fail closed).

### 4. Conecta y verifica

El modo recomendado es systemd, que mantiene el pin y el estado del perfil:

```bash
sudo systemctl enable --now lattice-resolver
sudo systemctl enable --now lattice-netd@<profile-uuid>
sudo lattice profile status --profile-id <profile-uuid>
ip -br addr | grep -E 'lp|lattice' || true
ip route
```

Para una prueba manual, conserva la misma clave de control y ejecuta:

```bash
sudo -E lattice profile connect --profile-id <profile-uuid>
```

Si no hay TUN, permisos o un perfil válido, el comando falla; no activa un
proxy alternativo ni deja tráfico abierto.

Para detener o renovar el perfil:

```bash
sudo lattice profile disconnect --profile-id <profile-uuid>
sudo -E lattice profile renew --bundle /secure/profile.offer.json
```

### 5. Prueba DNS y un servicio

Los nombres privados se resuelven desde rutas firmadas. En un host Linux con
`systemd-resolved` puedes comprobar una entrada así:

```bash
resolvectl query echo.lattice
```

Cuando el binding publica HTTPS y la CA privada está instalada, prueba el
servicio con `curl --fail --noproxy '*' https://<servicio>.coral/health` (o con
su alias `.reef`). El ejemplo Docker usa endpoints HTTP de prueba y los valida
con `network/tests/dev-client-e2e.sh`.

En el cliente Docker de desarrollo no existe `systemd-resolved`. Los scripts
de abajo suponen el stack de desarrollo ya levantado (contenedores
`lattice-lnp-e2e` y `lattice-dev-gateway`, con `/dev/net/tun`). Desde el host
Docker ejecuta el puente de DNS dividido y luego la prueba E2E:

```bash
network/tests/configure-dev-dns.sh
network/tests/dev-client-e2e.sh <profile-uuid>
```

El puente envía únicamente `.lattice`, `.coral` y `.reef` al resolver de Lattice
y conserva los resolvers públicos para el resto. Si consultas un nombre
público directamente al resolver Lattice, recibirás `REFUSED` por diseño.

### Diagnóstico rápido

- `profile status` no muestra perfiles: todavía no ejecutaste el enrolamiento o
  estás mirando otro `--state-dir`.
- `ping echo.lattice` dice *Name or service not known*: comprueba primero
  `resolvectl status`; en Docker vuelve a ejecutar
  `network/tests/configure-dev-dns.sh` y usa `dig @127.0.0.1 -p 5353
  echo.lattice` para aislar el problema de DNS.
- No aparece una interfaz `lp...`: el proceso no tiene TUN/permisos o el perfil
  fue rechazado. Revisa `journalctl -u lattice-netd@<profile-uuid>`; no
  desactives el kill-switch para “probar”.

## Cómo se nombran las cosas

Cada namespace tiene una función distinta:

| Nombre | Significado | Ejemplo |
| --- | --- | --- |
| `lttc://` | Deep link que activa un perfil y abre HTTPS | `lttc://alice.coral/health` |
| `*.coral` | Identidad de un participante o servicio delegado | `alice.coral`, `api.alice.coral` |
| `<hash>.coral` | Identidad canónica derivada del SPKI TLS del servicio | `<base32-sha256>.coral` |
| `*.reef` | Nombre legible registrado on-chain | `clipma.reef` |
| `*.lattice` | Infraestructura propia de la red | `resolver.lattice`, `echo.lattice` |

La IP virtual (`10.x`, `fd00:...`) sólo es una ruta actual. La identidad real
la fijan la firma del perfil, el certificado TLS y su pin SPKI. Un alias humano
es válido únicamente cuando está firmado y delegado por la identidad canónica.
Por eso el mismo servicio puede cambiar de Wi-Fi, Gateway o IP sin cambiar de
nombre.

Ejemplos:

```text
lttc://alice.coral/                  → https://alice.coral/
lttc://api.alice.coral/health        → https://api.alice.coral/health
lttc://clipma.reef/orders?id=42      → https://clipma.reef/orders?id=42
lttc://echo/health                    → https://echo.lattice/health
```

El parser acepta sólo `lttc://`. Rechaza `lattice://`, `lp://`, credenciales,
puertos explícitos, fragmentos, IP literales y hosts no canónicos. Chrome no
recibe una contraseña ni se configura con un proxy: el handler valida el deep
link, activa el perfil requerido y deja que Chrome conecte por HTTPS usando la
CA privada instalada en el dispositivo administrado.

## Qué incluye LNP/1

- **`lattice-net-core`**: frames de control, fragmentación acotada, perfiles,
  leases, políticas, validación URI y pinning TLS.
- **`lattice-netd`**: cliente QUIC, TUN, rutas, DNS, kill-switch y ciclo de vida
  del perfil; `lattice run --agent ...` exige aislamiento verificable.
- **`lattice-gatewayd`**: Gateway mTLS que autoriza perfil, agente, servicio o
  CIDR, protocolo y puerto antes de reenviar paquetes.
- **`lattice-resolver`**: resolver autoritativo sólo para `.lattice`, `.coral`
  y `.reef`; nunca filtra consultas privadas a DNS público.
- **`lattice-netctl`**: PKI X.509 privada, CSR, bundles, revocación y allowlists
  de egress.
- **`latticed`**: custodia local de claves Ed25519 y leases de agente breves.

QUIC aporta cifrado y control de congestión; Lattice no inventa criptografía.
LNP/1 anuncia MTU 1280 y limita tamaño, cantidad, tiempo y memoria de
reensamblado. Split-tunnel y full-tunnel son decisiones explícitas del perfil;
el full-tunnel necesita un Gateway de salida con allowlist.

## Aislamiento por agente

En Linux, el modo por agente crea un namespace dedicado y permite únicamente
loopback, la interfaz Lattice y el endpoint UDP exacto del Gateway:

```bash
sudo --preserve-env=LATTICE_CONTROL_PUBLIC_KEY_B64 \
  lattice run --agent bot1 --profile <profile-uuid> -- /ruta/a/tu-agente
```

Si el sistema no puede demostrar ese aislamiento, el comando se niega a
ejecutar. macOS y Windows sólo habilitarán per-app cuando sus políticas nativas
o MDM lo hagan verificable.

## Migración desde el overlay anterior

El overlay HTTP/Relay y las direcciones `lp://` quedan archivados: no hay
fallback de runtime. El migrador transforma una sola vez namespaces, servicios
y grants a bindings de IP virtual y reglas L3/L4; no copia claves privadas ni
certificados JSON antiguos.

```bash
npm run migrate:network -- \
  --agent bot1 --organization example \
  --gateway 203.0.113.10:7443 --gateway-name gateway.example.com \
  --gateway-pin <gateway-spki-sha256> \
  --service-tls-pin <service-spki-sha256> \
  --enrollment-token <one-time-token> --mode split \
  --out /secure/profile-template.json
```

Las autorizaciones HTTP sólo se conservan si se indica explícitamente
`--terminate-tls`; un paquete cifrado no implica por sí solo permiso HTTP.

## Estado por plataforma

- **Linux:** cliente instalable con TUN, systemd, `iproute2`, `nftables`, DNS
  dividido y namespaces. Es la única distribución de esta entrega.
- **macOS:** host `NEPacketTunnelProvider` compilable. Requiere Network
  Extension entitlement, firma y notarización de Apple.
- **Windows:** host `IVpnPlugIn`/MSIX compilable. Requiere firma de Microsoft y
  política de filtrado para per-app.
- **Móvil:** fuera de alcance.

## Desarrollo y validación

```bash
npm run build                 # TypeScript
npm run build:contracts       # ABI/bin de LatticeChain
npm run build:network         # workspace Rust LNP/1
npm run test:network          # pruebas Rust del workspace
npm run test:rust             # cliente Rust/LTP
cargo clippy --manifest-path network/Cargo.toml --workspace --all-targets -- -D warnings
```

Los tests de red privilegiados necesitan Linux con `/dev/net/tun`,
`iproute2`, `nftables`, `setpriv` y permisos de red. Las pruebas de macOS y
Windows se ejecutan en sus runners nativos. Antes de habilitar una VPN fuera
de un entorno local todavía deben completarse las pruebas E2E autenticadas,
DNS sin filtración, revocación, caída del control plane, bloqueo de bypass
IPv4/IPv6/DoH/proxy y una auditoría de seguridad fresca.

## Seguridad y operación

Registra sólo identidad/perfil, servicio o IP de destino, protocolo, bytes,
decisión, versión de política y huellas. Nunca registres payloads ni consultas
DNS completas. Revoca perfiles/certificados desde el control plane y renueva
antes de 90 días.

Más detalle:

- [Especificación de nombres](docs/lattice-naming-protocol.md)
- [LNP/1](docs/lnp-1.md)
- [Soporte de plataformas](docs/platform-support.md)
- [Esquema `lttc://`](docs/lattice-uri-scheme.md)
- [Runbook operativo](RUNBOOK.md)

## Estructura del repositorio

```text
network/       workspace Rust de LNP/1 (cliente, Gateway, resolver y PKI)
clients/rust/  cliente nativo LTP/1 y wrapper del comando `lattice`
daemon/        `latticed`, custodia local de claves
node/          control plane/overlay archivado para migración y auditoría
contracts/     LatticeChain y bindings on-chain
services/      servicios de ejemplo (incluido echo)
tests/         pruebas TypeScript
docs/          especificaciones y runbooks
```

Consulta los términos de licencia incluidos en el release que distribuyas.

Lattice está diseñada para fallar cerrada: un perfil ausente, una firma
inválida, una ruta vencida o un adaptador no verificable bloquea el tráfico en
lugar de degradar silenciosamente a HTTP, proxy o `lp://`.
