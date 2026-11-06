# ODD — Orchestration Design Document · OpenPassport `v1.0.0`

- **Estado:** Propuesto · 2026-11-04
- **Insumo:** [AUDIT-v1.0.0.md](AUDIT-v1.0.0.md) (8 P0, 11 P1, 9 P2)
- **Objetivo:** publicar `v1.0.0` como primera versión pública estable, cumpliendo los *release gates* de la auditoría (§4).

## 1. Principio rector: orquestación con workers baratos

> **La orquestación DEBERÁ utilizar workers baratos.** El modelo caro solo planifica, decide y revisa; nunca ejecuta trabajo mecánico.

Reglas obligatorias:

1. **Tier mínimo suficiente.** Cada paquete de trabajo (WP) se asigna al modelo más barato capaz de cerrarlo. Subir de tier es una excepción justificada, no la norma.
2. **El orquestador no escribe código.** Lee diffs, corre los gates, decide si se acepta y escala. Su gasto debe ser una fracción menor del total.
3. **Contexto fresco y acotado.** Cada worker arranca sin historial y recibe solo su brief: objetivo, archivos que le pertenecen, comando de gate y criterio de terminado. Nada de "lee todo el repo".
4. **El gate decide, no la opinión del worker.** Un WP está terminado cuando su comando de verificación sale en 0 y el orquestador revisa el diff. Si el worker dice "listo", eso no cuenta como evidencia.
5. **Escalado por fallo, no por miedo.** Tras **2 intentos fallidos** del gate, el WP sube un tier. Tras fallar en el tier 2, vuelve al orquestador para rediseñarlo, no se reintenta.
6. **Propiedad exclusiva de archivos.** Dos workers nunca tocan el mismo archivo en la misma ola. Cada worker trabaja en su propio worktree/rama.
7. **Tier 0 primero.** Lo que puede hacer un script determinista (format, vet, test, generar checksums, regenerar manifests) no se le encarga a un LLM.

### 1.1 Tiers

| Tier | Modelo | Uso | Ejemplos |
|---|---|---|---|
| T0 | Ninguno (scripts/CI) | Verificación y tareas deterministas | `go test`, `gofmt`, `pnpm audit`, `sha256sum`, rebuild de la plantilla |
| T1 | `claude-haiku-5-5` | Trabajo mecánico con instrucciones exactas | docs, LICENSE, workflows, plumbing de versión, borrar código muerto, tests a partir de vectores dados |
| T2 | `claude-sonnet-5-5` | Implementación con juicio local | fixes de seguridad, determinismo del builder, paridad Go↔TS, MCP fail-closed |
| T3 | `claude-opus-5-5` (orquestador) | Solo plan, decisiones de contrato, revisión final | fijar el contrato de hash, aprobar diffs P0, cortar el RC |

**Meta de mezcla:** ≥ 60 % de los WP en T1, ≤ 35 % en T2. T3 no tiene WP de implementación.

### 1.2 Implementación en Claude Code

- Defínanse los workers en `.claude/agents/` con `model:` en el frontmatter: `op-worker-haiku.md` (T1) y `op-worker-sonnet.md` (T2), con herramientas limitadas a `Read, Edit, Write, Grep, Glob, Bash`.
- El orquestador lanza cada WP con el tool `Agent` (`subagent_type` = el worker del tier, `isolation: "worktree"`) y espera su resultado. Los WP de una misma ola se lanzan en paralelo.
- **Plantilla de brief** (es lo único que recibe el worker):

```text
WP-XX — <título>
Objetivo: <1-2 frases>
Archivos que te pertenecen (solo estos): <lista>
No toques: todo lo demás.
Hallazgos que cierras: <IDs de la auditoría + resumen de 1 línea cada uno>
Gate (debe salir en 0): <comando exacto>
Terminado = gate en verde + test nuevo que falla sin tu cambio.
Límites: máx. 30 turnos; no instales dependencias nuevas sin decirlo; no hagas commit en main.
Entrega: rama, resumen de 5 líneas, salida del gate.
```

## 2. Decisiones previas (del titular, antes de la Ola 1)

| # | Decisión | Recomendación |
|---|---|---|
| D1 | Licencia única | **Apache-2.0** (la que ya anuncia el README; trae una cláusula de patentes útil para un "estándar"). Alternativa: MIT en todo. |
| D2 | Número de versión | **`v1.0.0`** tras pasar por `v1.0.0-rc.1`. El salto desde `v0.1.1` comunica estabilidad del contrato. |
| D3 | Contrato canónico de hash | **Bytes crudos UTF-8 con LF obligatorio** (verify rechaza CRLF, no lo normaliza). Self-hash = sustituir el **valor del campo** `files[path=manifest.json].sha256` por 64 ceros. JSON con 2 espacios, claves en orden fijo y `\n` final. `normalize` solo convierte CRLF/CR → LF, sin `trim`. |
| D4 | `internal/hasher` y `pkg/schema` ("Contract V0 / Velo") | **Eliminar** de este repo. Si Velo los necesita, que vivan en su propio módulo. |
| D5 | Nombre del CLI en npm | No publicar `@multiversa/passport-core-cli`. La plantilla usará el binario del release, verificado con checksum. Opcionalmente, reservar el nombre en npm para neutralizar el squatting. |

## 3. Paquetes de trabajo

| WP | Título | Tier | Archivos (propiedad exclusiva) | Cierra | Gate |
|---|---|---|---|---|---|
| WP-00 | Partir `core.go` en `init.go`, `lint.go`, `build.go`, `verify.go`, `export.go` **sin cambiar comportamiento** | T1 | `internal/passport/*.go` | (habilita la Ola 1) | `go build ./... && go vet ./...` + verify de la plantilla en PASS |
| WP-01 | `docs/SPEC.md` (contrato D3) + vectores dorados en `testdata/vectors/` (≥ 6 casos: LF, CRLF, `\r` suelto, UTF-8 no ASCII, perfil vacío, mayúsculas/minúsculas en rutas) | T2 (el orquestador valida el contrato) | `docs/SPEC.md`, `testdata/**` | M6, base de H3/H6 | revisión del orquestador |
| WP-02 | Rutas seguras: `safeJoin` (rechaza `..`, rutas absolutas, symlinks que salgan del dir) en verify y export; export verifica antes de empaquetar, propaga todos los errores, orden ordenado, cabeceras tar normalizadas (mtime=0, uid/gid=0, modo 0644) | T2 | `internal/passport/export.go`, `verify.go`, `paths.go`, `*_test.go` | B1, B2, B3, H4 | `go test -race ./internal/...` con tests de traversal y de export byte-idéntico |
| WP-03 | Build determinista: `--as-of` (por defecto el `asOf` existente o la fecha UTC), `normalize` sin trim, slices no nulos, lista de exclusión (`.git/`, `node_modules/`, `*.tar.gz`, `generation.receipt.json`) con inclusión explícita de `.gitattributes`, orden por bytes, `--fix-crlf` desactivado por defecto, errores del receipt propagados, self-hash por campo y validación hex | T2 | `internal/passport/build.go`, `hasher.go`, `types.go`, `*_test.go` | H2, H3, H5, H6 (Go), H7, H8, H11 | `go test ./...` + vectores de WP-01 |
| WP-04 | Paridad TS con SPEC: mismas exclusiones, orden por bytes (no `localeCompare`), `toLF` sin trim, sin seguir symlinks, `safeJoin` en el validator, tests sobre `src` vía `tsx` o build previo en el script de test | T2 | `packages/passport-core/**` | H2, H6 (TS), B1 (TS), M5 | `pnpm --filter passport-core test` + vectores |
| WP-05 | MCP fail-closed: perfil desconocido o manifest ausente/inválido → error; visibilidad aplicada siempre según `files[].visibility`; parseo de `--passport <dir>` y `PASSPORT_DIR`; quitar `zod` directo; tests con un cliente MCP en memoria | T2 | `packages/mcp-passport/**` | H1, B6 (código) | `pnpm --filter mcp-passport test` |
| WP-06 | CLI: versión vía `-ldflags "-X main.Version=..."` (`dev` por defecto), errores a stderr, códigos de salida documentados (0 ok, 1 fallo de verificación, 2 uso), `--json` en lint/verify, `--no-emoji` | T1 | `cmd/openpassport/**` | B8, M2 | `go build` + golden tests del output |
| WP-07 | CI y release: `ci.yml` (matrix ubuntu/macos/windows: `go vet`, `go test -race`, `pnpm -r build test`, conformidad cruzada con los vectores, `pnpm audit --prod --audit-level high`, smoke test del README); `release.yml` con actions fijadas por SHA, `go-version-file: go.mod`, `CGO_ENABLED=0 -trimpath -ldflags`, targets `linux/arm64` y `windows/arm64`, `SHA256SUMS`, `actions/attest-build-provenance`, tag solo con patrón semver `v[0-9]+.[0-9]+.[0-9]+*`, y que el release dependa del CI | T1 | `.github/workflows/**` | B7, H10 | `actionlint` + ejecución en una rama |
| WP-08 | Legal y comunidad: `LICENSE` (D1), `SECURITY.md` (canal de reporte privado), `CHANGELOG.md` (Keep a Changelog desde `v0.1.0`), `CONTRIBUTING.md`, campo `license` en `package.json` y la plantilla | T1 | archivos raíz, `packages/*/package.json` (solo `license`/`version`), `templates/**/LICENSE` | B4, M6 | `gh repo view --json licenseInfo` tras el merge |
| WP-09 | Dependencias: subir `@modelcontextprotocol/sdk` a una versión que use `zod` ≥ 4.6.6, o `pnpm.overrides`; regenerar el lockfile | T1 | `packages/mcp-passport/package.json`, `pnpm-lock.yaml`, `package.json` raíz | H9 | `pnpm audit --prod` sin altos |
| WP-10 | Borrar código muerto (D4) | T1 | `internal/hasher/`, `pkg/schema/` | M1 | `go build ./... && go test ./...` |
| WP-11 | README y plantilla: config MCP real, recursos/tools reales, badge de Go correcto, sección de seguridad y exit codes; el CI de la plantilla descarga el binario del release y verifica `SHA256SUMS` (sin `npx` a paquetes inexistentes); `technicalAuthority` configurable; regenerar el manifest de la plantilla con el builder nuevo (T0) | T1 | `README.md`, `templates/**` | B5, B6 (docs), M7, M8, M9 | smoke test de WP-07 en verde |
| WP-12 | Conformidad y RC: correr todos los gates, cortar `v1.0.0-rc.1`, smoke test en los 3 SO, 72 h de soak, cortar `v1.0.0` | T0 + T3 | tags | Gates §4 | Gates §4 de la auditoría |

## 4. Olas y paralelismo

```text
Ola 0 (paralela)    WP-00 · WP-01 · WP-08* · WP-09 · WP-10      *requiere D1
                       │
Ola 1 (paralela)    WP-02 · WP-03 · WP-04 · WP-05 · WP-06 · WP-07
                       │   (WP-02/03 dependen de WP-00; WP-03/04 de WP-01)
Ola 2               WP-11                 (depende de WP-05, WP-06 y WP-07)
                       │
Ola 3               WP-12  → v1.0.0-rc.1 → soak 72 h → v1.0.0  (tag lo aprueba el titular)
```

- Máx. 6 workers simultáneos. Ningún par de WP de la misma ola comparte archivos (ver columna "Archivos").
- El orquestador hace el merge en orden: Ola N completa y en verde antes de abrir la Ola N+1.
- Cada merge vuelve a correr el CI completo (T0); si se rompe algo que ya estaba en verde, el WP culpable se reabre en su mismo tier.

## 5. Control de costo y calidad

| Control | Regla |
|---|---|
| Presupuesto por WP | T1: 30 turnos · T2: 60 turnos. Al agotarse, el WP se corta y vuelve al orquestador. |
| Revisión del orquestador | Solo el diff y la salida del gate, sin rehacer el trabajo. Los WP P0 (02, 03, 05) llevan revisión obligatoria línea por línea. |
| Métrica de la ola | % de WP cerrados en el tier asignado (meta ≥ 80 %) y nº de escalados. Si una categoría escala de forma sistemática, en la siguiente ola se asigna directo al tier superior. |
| Anti-regresión | Cada hallazgo de la auditoría se cierra con un test con su ID en el nombre (`TestB1_ExportRejectsTraversal`, etc.). |
| HITL | El push de tags, la publicación del release y cualquier `npm publish` los aprueba el titular. Ningún worker tiene permiso de push a `main` ni de crear tags. |

## 6. Riesgos

| Riesgo | Mitigación |
|---|---|
| Cambiar el contrato de hash (D3) invalida los manifests de `v0.1.x` | `verify` reconoce los manifests `schemaVersion: 1` antiguos y avisa con un mensaje de migración (`openpassport build` los re-sella). Documentarlo en el CHANGELOG como *breaking*. |
| Un worker barato "arregla" el test en vez del código | El gate incluye los vectores dorados de WP-01, que solo el orquestador puede modificar. |
| Divergencia futura Go/TS | El job de conformidad cruzada de CI es obligatorio para hacer merge. |
| El nombre `@multiversa/passport-core-cli` sigue libre en npm | D5: quitarlo de la plantilla en WP-11 y, opcionalmente, reservarlo. |
