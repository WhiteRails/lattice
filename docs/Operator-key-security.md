# Seguridad de claves del operador (owner del contrato)

Este documento resume **cómo guardar la clave privada del owner de `LatticeChain` fuera del repositorio** y reducir el riesgo de fuga o commit accidental.

## Principios

1. **Nunca** commitear claves privadas, keystores sin cifrar ni `.env` con secretos al repo.
2. Preferir **`--key-file`** en el CLI apuntando a un archivo **fuera del árbol del proyecto** (por ejemplo `~/.secrets/lattice-owner.key` o un volumen cifrado).
3. Permisos mínimos en disco: `chmod 600` sobre el archivo de clave; directorio padre sin lectura para otros usuarios.
4. En producción, preferir **hardware wallet** (Ledger/Trezor) o **HSM/KMS** y firmar transacciones sin exponer la clave en el host.

## macOS (ejemplo rápido)

```bash
mkdir -p ~/.secrets/lattice
chmod 700 ~/.secrets/lattice
# Guarda solo la clave hex en un archivo de una línea:
nano ~/.secrets/lattice/owner.hex
chmod 600 ~/.secrets/lattice/owner.hex
```

Uso con el CLI:

```bash
npm run lattice -- chain deploy --rpc "$RPC" --key-file "$HOME/.secrets/lattice/owner.hex"
```

## Variables de entorno (sin archivo en el repo)

```bash
export LATTICE_OWNER_KEY_FILE="$HOME/.secrets/lattice/owner.hex"
npm run lattice -- chain cert-type register AgentCert --level 1 --rpc "$RPC" --key-file "$LATTICE_OWNER_KEY_FILE" --contract "$ADDR"
```

No pongas `export PRIVATE_KEY=0x...` en scripts versionados.

## Keychain (opcional)

Puedes almacenar un secreto en el llavero y extraerlo a un temporal solo para la sesión (borrar después); el detalle depende de tu flujo de CI/CD.

## Rotación y `transferOwnership`

Si comprometes la clave del deployer/owner:

1. Despliega un contrato nuevo **o** transfiere ownership con una clave aún segura:
   `lattice chain ownership transfer <nuevoOwner> --rpc … --key-file … --contract …`
2. Rota todas las claves que hayan tocado hosts comprometidos.

## `.gitignore`

El repo ignora patrones típicos (`*.pem`, `.env`, `secrets/`, etc.). **Comprueba** con `git status` antes de cada commit.
