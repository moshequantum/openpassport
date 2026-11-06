# Especificación Canónica de OpenPassport (C1 Standard)

- **Versión de la especificación:** 1.0.0
- **Identificador de contrato:** `C1` / `OpenPassport v1.0`
- **Estado:** Estándar Aprobado

---

## 1. Modelo de Datos y Archivos

Un paquete OpenPassport es un directorio estructurado que encapsula el contexto de un sistema, agente o titular de IA mediante capas canónicas auditables.

### 1.1 Capas Canónicas Obligatorias
1. `01-IDENTITY.md` — Identidad estable, propósito, qué es y qué NO es.
2. `02-DOCTRINE.md` — Axiomas innegociables, principios y directrices fundamentales.
3. `03-VOICE.md` — Tono, whitelist/blacklist lingüística y matriz de estilo.
4. `04-OFFER.md` — Oferta comercial, propuesta de valor y entregables.
5. `05-GOVERNANCE.md` — Jerarquía de decisiones, autoridades y reglas de precedencia.
6. `06-CURRENT-STATE.md` — Estado operativo, metas activas y restricciones temporales.
7. `07-EVIDENCE.md` — Pruebas empíricas, fuentes y citas de verdad.

Archivos de soporte canónicos:
- `MASTER-PROMPT.md` — Prompt interpretador de la jerarquía dura.
- `README.md` — Guía de uso y originador del paquete.
- `.gitattributes` — Configuración de repositorio que impone `eol=lf`.
- `manifest.json` — Manifiesto criptográfico y mapa de integridad.
- `generation.receipt.json` — Recibo determinista de compilación.

---

## 2. Contrato Criptográfico de Integridad (C1)

### 2.1 Algoritmo de Hashing y Codificación
- Algoritmo: **SHA-256** (`sha256`).
- Codificación: Cadena hexadecimal en minúsculas de 64 caracteres (`[0-9a-f]{64}`).
- Bytes base: Bytes crudos UTF-8 exactos.

### 2.2 Política de Saltos de Línea (LF Puro)
- Todo archivo de texto (`.md`, `.json`, `.txt`) **DEBE** tener exclusivamente saltos de línea LF (`\n`, `0x0A`).
- Los saltos de línea CRLF (`\r\n`, `0x0D 0x0A`) y CR aislados (`\r`, `0x0D`) están terminantemente prohibidos en modo estricto.
- La verificación (`verify`) **rechaza de plano** archivos con bytes `0x0D`, sin normalizarlos en memoria.
- La función de normalización (`ToLF` / `toLF`) transforma `\r\n` y `\r` en `\n` **sin ejecutar `trim()` / `TrimSpace()`**, preservando sangrías y líneas vacías iniciales y finales.

### 2.3 Contrato de Auto-Sellado (`manifestSelfHash`)
El archivo `manifest.json` contiene la lista de todos los archivos del pasaporte y su propio hash. Para resolver la paradoja de autorreferencia determinista:
1. En el JSON del manifiesto, la entrada `files` cuyo `path == "manifest.json"` almacena un placeholder de 64 ceros:
   `"0000000000000000000000000000000000000000000000000000000000000000"`.
2. El JSON se formatea con sangría de 2 espacios, sin escape de caracteres HTML, claves en orden canónico y `\n` al final.
3. Se calcula el SHA-256 de los bytes UTF-8 resultantes.
4. Ese valor SHA-256 resultante se inyecta en el campo `files[path=manifest.json].sha256`.
5. Durante la verificación, se reemplaza únicamente el valor actual de dicho hash por los 64 ceros y se compara contra el hash recalculado.

### 2.4 Ordenamiento Canónico de Rutas
- Todas las rutas se normalizan usando separador `/` (Forward Slash).
- El ordenamiento de las listas `files` y `profiles[].files` **DEBE** realizarse por orden lexicográfico de bytes ASCII/UTF-8 crudo (e.g. `a < b`), **nunca** mediante `localeCompare` o comparaciones insensibles a mayúsculas.

---

## 3. Seguridad y Límites de Ejecución

### 3.1 Prevención de Path Traversal
- Toda ruta referenciada en un perfil o manifiesto debe resolverse mediante `SafeJoin`.
- Se rechaza de inmediato cualquier ruta con componentes `..`, rutas absolutas (`/` o `C:\`), o enlaces simbólicos que resuelvan fuera del directorio raíz del pasaporte.

### 3.2 Empaquetamiento Determinista (`export`)
- `export` valida obligatoriamente la integridad del paquete completo antes de empaquetar.
- El archivo `.tar.gz` exportado debe ser byte-idéntico en cada ejecución:
  - Entradas en orden alfabético estricto de bytes.
  - Timestamps de cabecera `ModTime` fijados a 0 (Unix Epoch).
  - `Uid = 0`, `Gid = 0`, `Uname = ""`, `Gname = ""`.
  - Permisos de archivo normalizados (`0644`).

### 3.3 Servidor MCP Fail-Closed
- Si el pasaporte solicitado no existe, el manifiesto es inválido o no pasa la verificación criptográfica, el servidor responde con error inmediato.
- Bajo ninguna circunstancia un error de perfil provocará la exposición de archivos privados o no autorizados.
