# Auditoría de estabilización — OpenPassport hacia `v1.0.0`

- **Fecha de corte:** 2026-11-04
- **Commit auditado:** `30ba5f1` (`main`, tag público más reciente: `v0.1.1`)
- **Alcance:** CLI Go (`cmd/`, `internal/`, `pkg/`), paquetes TS (`packages/passport-core`, `packages/mcp-passport`), plantilla (`templates/open-passport-template`), CI/release, documentación y licencia.
- **Método:** lectura completa del código (41 archivos versionados) + pruebas ejecutadas localmente (Go 1.27.3, Node 26.13, pnpm 9.15).

## 1. Veredicto

**No está listo para un tag público estable.** El núcleo funciona en el camino feliz (build ↔ verify cruzados entre Go y TS pasan), pero hay **8 bloqueantes**: una vulnerabilidad de path traversal confirmada en `export`, un riesgo de cadena de suministro en la plantilla, licencia contradictoria, documentación que no corresponde al código y cero pruebas/CI en Go. El trabajo para llegar a `v1.0.0` está planificado en [ODD-v1.0.0.md](ODD-v1.0.0.md).

## 2. Lo que sí funciona (evidencia)

| Prueba | Resultado |
|---|---|
| `go vet ./...` / `go build` | OK |
| `pnpm -r build` / `pnpm -r test` (3 tests) | OK |
| `openpassport verify` + `lint` sobre la plantilla | PASS |
| Build Go → verify TS | PASS |
| Build TS → verify Go | PASS |
| Rebuild Go el mismo día (idempotencia del manifest) | Idéntico |

## 3. Hallazgos

Severidad: **P0** = bloquea el tag · **P1** = debe corregirse antes de `v1.0.0` · **P2** = deuda aceptable con issue abierto.

### P0 — Bloqueantes

| ID | Hallazgo | Evidencia | Ubicación |
|---|---|---|---|
| B1 | **Path traversal en `export`.** Las rutas de `profiles[].files` se usan sin validar; un manifest con `../secret.txt` mete archivos externos en el bundle. `verify` (Go y TS) también lee fuera del directorio. | Reproducido: el `.tar.gz` contenía `../secret.txt`. | `internal/passport/core.go:410-450`, `:368`; `packages/passport-core/src/validator.ts:100` |
| B2 | **`export` no verifica la integridad antes de empaquetar.** Un manifest manipulado se exporta con código de salida 0, aunque el README lo describe como "authenticated profile bundle". | Reproducido tras editar el manifest. | `core.go:387` |
| B3 | **`export` ignora errores en silencio** (`stat`, `FileInfoHeader`, `open`, `io.Copy`): puede salir un bundle incompleto con éxito. | Lectura de código. | `core.go:430-449` |
| B4 | **Licencia contradictoria y ausente.** El README dice Apache-2.0, los `package.json` y la plantilla dicen MIT, y no existe `LICENSE` en la raíz. GitHub reporta `licenseInfo: null`: legalmente el repo público queda "todos los derechos reservados". | `gh repo view` | raíz, `README.md:9,158`, `packages/*/package.json` |
| B5 | **Riesgo de cadena de suministro en la plantilla.** El CI de la plantilla ejecuta `npx --yes @multiversa/passport-core-cli`, un paquete que **no existe en npm** (E404). Cualquiera puede registrar ese nombre y ejecutar código en el CI de todos los usuarios de la plantilla. Además, el fallback solo comprueba el self-hash, no los archivos. | `npm view` → E404 | `templates/open-passport-template/.github/workflows/passport-verify.yml:24` |
| B6 | **El README describe un MCP que no existe.** La config de ejemplo pasa `--passport <dir>`, pero `cli.ts` toma `argv[2]` como directorio (queda `"--passport"`). Los recursos `passport://current-state` y las tools `get_layer_content` y `check_claim_evidence` no existen. | Lectura de código. | `README.md:136-152`, `packages/mcp-passport/src/cli.ts:4` |
| B7 | **Cero pruebas en Go y ningún CI en push/PR.** Solo existe `release.yml`, que compila lo que se etiquete sin correr nada. | `go test ./...` → "no test files" | `.github/workflows/` |
| B8 | **Versiones incoherentes.** El CLI imprime `v1.0.0` (constante fija), los paquetes npm dicen `1.0.0` y los tags publicados son `v0.1.0`/`v0.1.1`. No se inyecta la versión con `-ldflags`. | `openpassport version` | `cmd/openpassport/main.go:12` |

### P1 — Antes de `v1.0.0`

| ID | Hallazgo | Ubicación |
|---|---|---|
| H1 | **MCP falla abierto (fuga de privacidad).** En `resolve_context`, si el perfil no existe o el manifest falta o es inválido, `allowedFiles` queda `null` y se sirven **todas** las capas (gobernanza, oferta, estado). El filtro de visibilidad solo se aplica si el id del perfil contiene la palabra `"public"`. | `packages/mcp-passport/src/server.ts:226-271` |
| H2 | **`--fix-crlf` altera el contenido, no solo los saltos de línea.** `ToLF`/`toLF` hacen `TrimSpace`/`trim()` y borran los espacios y líneas iniciales y finales (reproducido). Además, `--fix-crlf` está activado por defecto y reescribe archivos sin avisar. | `internal/passport/hasher.go:17-23`, `normalizer.ts:4`, `main.go:121` |
| H3 | **Divergencia de esquema Go/TS.** Go serializa los slices vacíos como `"files": null` (reproducido); TS emite `[]`. | `core.go:455-475` |
| H4 | **`export` no es determinista.** El orden de las entradas sale de iterar un `map`, y el mtime y los permisos van en el tar. Dos exportaciones del mismo directorio dan bytes distintos (reproducido). | `core.go:428` |
| H5 | **El build no es reproducible entre días.** `asOf = time.Now()` (hora local) cambia el hash del manifest cada día aunque el contenido no cambie. Go no tiene `--as-of`; TS sí. | `core.go:118` |
| H6 | **Dos builders, dos conjuntos de archivos.** Go excluye todo lo que empieza por `.git` (incluido `.gitattributes`, cuyo `case` nunca se ejecuta, y `.github/`). TS incluye `.gitattributes`, `.github/`, `node_modules/`, etc. Go ordena por bytes y TS con `localeCompare`. Para el mismo directorio salen manifests distintos. | `core.go:139`, `builder.ts:42-56,145` |
| H7 | **El build recorre todo el árbol sin lista de exclusión.** Hashea bundles `.tar.gz` previos, `node_modules`, etc. En TS, `statSync` sigue symlinks y puede entrar en bucle. | `core.go:130`, `builder.ts:48` |
| H8 | **El self-hash reemplaza la primera aparición del hash en todo el texto** (`strings.Replace(..., 1)`), no el campo concreto, y no valida que sea hex de 64 caracteres. | `internal/passport/hasher.go:32-40` |
| H9 | **Dependencia con advisory alto:** `zod@3.25.76` (GHSA-mrhx-c7xc-m3w5, agotamiento de memoria), transitiva vía `@modelcontextprotocol/sdk`. `zod` se declara directamente pero no se usa. | `pnpm audit` |
| H10 | **Pipeline de release débil:** no hay `SHA256SUMS` ni firma/provenance, las actions no están fijadas por SHA, `go-version: '>=1.22'` es flotante mientras `go.mod` exige 1.27.1, falta `-trimpath`/`CGO_ENABLED=0`, no hay builds `linux/arm64` ni `windows/arm64`, y cualquier tag `v*` dispara el release. | `.github/workflows/release.yml` |
| H11 | **Se ignoran los errores al escribir el receipt**, y su `status` siempre es `"pass"`. | `core.go:316-323` |

### P2 — Deuda con issue

| ID | Hallazgo |
|---|---|
| M1 | Código muerto con otro contrato: `internal/hasher` y `pkg/schema` ("Contract V0 / Velo") no se usan. `pkg/` es importable públicamente, así que se convertiría en API pública sin querer. |
| M2 | Los errores van a stdout, no a stderr. No hay salida `--json` para CI. Los emojis en la salida rompen algunas consolas de Windows. El CLI está en español y el README en inglés. |
| M3 | `HasCRLF` marca cualquier `\r` suelto, pero el mensaje dice "CRLF". |
| M4 | `lint` promete "consistencia", pero no valida el manifest frente al disco. |
| M5 | Los tests TS importan `dist/` (requieren build previo). Solo hay 3 y ninguno cubre el MCP. |
| M6 | Faltan `SECURITY.md`, `CHANGELOG.md`, `CONTRIBUTING.md` y una **especificación escrita del contrato de hash**, clave para la promesa de determinismo entre lenguajes. |
| M7 | `technicalAuthority` viene fijo con un cargo personal en el manifest de cada usuario. |
| M8 | El manifest de la plantilla no se generó con el builder actual (no lista `LICENSE`): verifica bien, pero un rebuild lo cambia. |
| M9 | El badge del README dice Go ≥ 1.22, pero `go.mod` exige 1.27.1. |

## 4. Criterios de salida para `v1.0.0` (release gates)

Todos deben estar en verde. Los verifica el orquestador, no el worker que hizo el cambio.

1. Cero hallazgos P0 y P1 abiertos (cada uno cerrado con un test que lo reproduce).
2. `go test -race ./...` y `pnpm -r test` en verde en Linux, macOS y Windows (CI matrix).
3. **Conformidad cruzada:** los vectores dorados de `testdata/vectors/` producen manifests **byte a byte idénticos** en Go y TS con `--as-of` fijo.
4. Build reproducible: dos builds del binario en CI dan el mismo SHA-256.
5. `pnpm audit --prod` sin advisories altos o críticos.
6. Un solo `LICENSE` en la raíz, coherente en README, `package.json` y plantilla.
7. Cada comando, flag, recurso y tool del README se ejecuta tal cual en un smoke test de CI.
8. El release publica binarios, `SHA256SUMS` y attestation de provenance.
9. `v1.0.0-rc.1` publicado y probado ≥ 72 h sin regresiones antes del tag final.
