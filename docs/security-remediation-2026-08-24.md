# Remediación del informe de seguridad 2026-08-24

Este documento reconcilia los 41 hallazgos HIGH de `CLAUDE-SECURITY-20260824-203331/CLAUDE-SECURITY-RESULTS.md` con el árbol de trabajo actual. El informe fue una revisión estática de `node/` en una revisión anterior y no sustituye un nuevo escaneo independiente. Los estados de abajo significan que existe corrección en código y regresión local; no son una certificación de despliegue ni cubren los 76 candidatos que el informe no llegó a verificar.

| Causa raíz | Hallazgos | Corrección actual | Evidencia local |
| --- | --- | --- | --- |
| Autenticación overlay basada en clave del remitente | F1, F11, F15, F19, F22, F23, F25, F28, F34 | En modo local el HMAC usa sólo `overlaySecret`; en mesh, la clave ECDH se deriva sólo de una clave de peer ya validada por registro/ruta. Un fallo de parseo devuelve `false`. | `tests/security-hardening.test.ts` y `tests/distributed.test.ts` |
| Principal de agente no autenticado en gateway | F14, F24 | La petición lleva `agent_proof`: el nombre, método, host, URL, fecha y hash de cuerpo se verifican con clave fijada o issuer confiable. `msg.source` debe ser igual al principal firmado. | `tests/security-hardening.test.ts`, `tests/issuer-trust.test.ts`, `tests/distributed.test.ts` |
| Secuestro del rendezvous de gateway oculto | F2, F17, F18, F21, F39 | El registro exige identidad gateway validada y una ruta autoritativa existente cuya clave y, en mesh, `nodeLabel`, coincidan. La respuesta se vuelve a validar contra esa misma identidad. | `tests/distributed.test.ts` y verificaciones de identidad en `node/relay.ts` |
| Traversal/equivalencia de nombres y bypass de revocación | F3, F5, F6, F8, F9, F13, F20, F33 | `normalizeAgentName` impone un único formato; state y policy resuelven paths bajo directorios contenedores; revocación usa el nombre canónico y la firma incluye el agente. | `tests/security-hardening.test.ts` |
| DoS por mensajes malformados, recursión o excepciones no atendidas | F4, F7, F12, F16, F26, F27, F29, F30, F36, F37, F38, F40, F41 | Schema estricto y tamaño máximo de overlay, clave X25519 validada, profundidad/cantidad de JSON acotada, handlers con captura y errores de chain convertidos a rechazo de peer. El registry captura fallos de body/canonicalización. | `tests/security-hardening.test.ts`, `tests/distributed.test.ts`, `tests/federation.test.ts` |
| Ruta `.id` y caché de federation como autoridad | F31, F32 | `.id` sólo toma endpoints de routing-cache local autenticado y exige que la clave coincida con la dirección; federation se consulta por nombre, se verifica y no se re-sella en el cache local. | `tests/security-hardening.test.ts`, `tests/federation.test.ts` |
| Socket de firma compartido entre contenedores | F10 | Cada ejecución Docker usa un directorio de socket aleatorio, privado y montado sólo de lectura; el modo C elimina el PEM antes de montar el directorio. | Revisión de `node/runner.ts`; prueba de interoperabilidad C/Rust en `clients/rust/tests/native_daemon.rs` |
| Smuggling HTTP hacia backend | F35 | Gateway allowlistea método, normaliza URL, rechaza framing/hop-by-hop y headers Lattice, reconstruye `Host` y `Content-Length` desde el cuerpo decodificado. | `node/gateway.ts` y suite TypeScript completa |

## Límites de la conclusión

- La cobertura anterior fue sólo `node/`; `core`, contratos, servicios, CI y dependencias necesitan una revisión independiente para afirmar seguridad de repositorio completo.
- Los 76 candidatos deduplicados no revisados por el panel del informe no están clasificados como corregidos por este documento.
- Antes de producción hay que ejecutar de nuevo el escaneo, pruebas autenticadas de una topología distribuida y observación operativa de rechazos, timeouts y journaling.
