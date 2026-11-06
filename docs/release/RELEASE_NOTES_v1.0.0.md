# OpenPassport v1.0.0 — Production-Ready Release 🌐🛡️

We are thrilled to announce the official **v1.0.0** release of **OpenPassport**: a deterministic, cryptographically verifiable context passport standard and engine built for AI agents, multi-agent swarms, and human operators.

![OpenPassport Banner](https://raw.githubusercontent.com/moshequantum/openpassport/main/docs/assets/openpassport-banner.svg)

---

### 🚀 Highlights

- **C1 Canonical Integrity Standard:** Pure LF (`0x0A`) byte guarantees and deterministic SHA-256 self-hash calculation with zero tolerance for trailing whitespace tampering or platform newline variations.
- **Fail-Closed Security:** Comprehensive path traversal defenses (`SafeJoin`), sandboxed layer resolution, and fail-closed privacy controls across public and internal context layers.
- **Model Context Protocol (MCP) Server:** Native `packages/mcp-passport` exposing tools (`get_layer_content`, `check_claim_evidence`, `resolve_context`, `verify_passport_integrity`, `get_passport_manifest`) and direct URI resources (`passport://current-state`, `passport://state`) for Claude Desktop, Cursor, Antigravity, and any MCP client.
- **Multi-Platform Go Engine & CLI:** Zero-dependency, ultra-fast Go binaries with standardized exit codes, JSON output mode (`--json`), and terminal formatting flags (`--no-emoji`).
- **TypeScript Reference Implementation:** Zero-vulnerability core SDK (`@multiversa/passport-core`) with cross-engine vector validation.
- **Deterministic Export Engine:** Reproducible `.tar.gz` export with unified exclusion rules (`.git`, `node_modules`, `*.tar.gz`, `receipts`), sorted tar headers, and fixed epoch timestamps.

---

### 📦 Pre-compiled Binaries & Verification

Every artifact is cryptographically hashed in `SHA256SUMS` and backed by GitHub Actions provenance attestations:

| Platform | Architecture | Binary |
| :--- | :--- | :--- |
| **Linux** | `x86_64` (amd64) | `openpassport-linux-amd64` |
| **Linux** | `aarch64` (arm64) | `openpassport-linux-arm64` |
| **macOS** | `Apple Silicon` (arm64) | `openpassport-darwin-arm64` |
| **macOS** | `Intel` (amd64) | `openpassport-darwin-amd64` |
| **Windows** | `x86_64` (amd64) | `openpassport-windows-amd64.exe` |
| **Windows** | `ARM64` | `openpassport-windows-arm64.exe` |

```bash
# Verify checksums
sha256sum -c SHA256SUMS
```

---

### 🛠️ Quick Start

#### Install with Go
```bash
go install github.com/moshequantum/openpassport/cmd/openpassport@v1.0.0
```

#### Run with MCP
```json
{
  "mcpServers": {
    "openpassport": {
      "command": "node",
      "args": ["/path/to/openpassport/packages/mcp-passport/dist/cli.js", "--passport", "/path/to/my-passport"]
    }
  }
}
```

---

### 📜 What's Changed
* **Audit & ODD Stabilization Gate:** Full remediation of P0/P1/P2 audit findings (B1–B8, H1–H11, M1–M9) merged via #1.
* **Full Changelog**: https://github.com/moshequantum/openpassport/compare/v0.1.1...v1.0.0
