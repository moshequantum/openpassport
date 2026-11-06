# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-05

### Added
- Standardized canonical specification in `docs/SPEC.md`.
- Cryptographic verification test suite with cross-language golden vectors (`testdata/vectors/`).
- Package `pkg/verify` exposing public C1 verification API with strict tamper detection.
- Path traversal hardening with canonical `SafeJoin` in export and verification.
- Deterministic archive builder (`export`) with zeroed timestamps, canonical modes, and sorted file entries.
- Automated multi-platform CI matrix (Linux, macOS, Windows) and provenance-attested release workflow.
- Private security reporting policy (`SECURITY.md`) and Apache-2.0 licensing across all packages.

### Changed
- Standardized hash contract: UTF-8 raw bytes, LF line endings, 64-zero placeholder for `manifest.json`.
- Fail-closed security architecture across MCP server (`@multiversa/mcp-passport`).
- Replaced monolithic `core.go` with modular implementations (`init.go`, `lint.go`, `build.go`, `verify.go`, `export.go`).
- Upgraded dependencies and patched transient Zod memory exhaustion vulnerability (GHSA-mrhx-c7xc-m3w5).

### Deprecated
- Contract V0 and legacy manifest schemas (`pkg/schema`).

## [0.1.1] - 2026-10-28

### Fixed
- Fixed PNPM workspace configuration for building `@multiversa/mcp-passport`.

## [0.1.0] - 2026-10-27

### Added
- Initial OpenPassport engine and CLI compiler in Go.
- Zero-dependency TypeScript runtime (`@multiversa/passport-core`).
- Model Context Protocol server (`@multiversa/mcp-passport`).
- Starter template with 7 canonical context layers (`templates/open-passport-template`).
