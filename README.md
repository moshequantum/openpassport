<div align="center">

# 🌐 OpenPassport

**The Deterministic Context & Cryptographic Integrity Engine for AI Agents**

[![Release](https://img.shields.io/github/v/release/moshequantum/openpassport?color=00E5FF&label=Release&style=flat-square)](https://github.com/moshequantum/openpassport/releases)
[![Go Version](https://img.shields.io/badge/Go-%3E%3D%201.22-7C4DFF?style=flat-square&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache--2.0-00E676?style=flat-square)](LICENSE)
[![Verification](https://img.shields.io/badge/Integrity-SHA--256%20Deterministic-FFD600?style=flat-square)](#cryptographic-integrity-seal)
[![MCP](https://img.shields.io/badge/MCP-Native%20Server-white?style=flat-square&logo=anthropic)](#model-context-protocol-mcp)

<p align="center">
  Stop context drift and LLM hallucinations. OpenPassport compiles raw business discovery into an immutable, cryptographically sealed 7-layer semantic context package.
</p>

[Quickstart](#quickstart) • [The 7 Semantic Layers](#the-7-canonical-layers) • [Precedence Hierarchy](#mathematical-precedence-hierarchy) • [CLI Commands](#cli-reference) • [MCP Server](#model-context-protocol-mcp)

</div>

---

## ⚡ The Problem: Context Drift in the Agentic Age

When autonomous AI agents (Cursor, Claude Code, Windsurf, Devin) build or maintain software, they suffer from three fatal flaws:
1. **Context Drift:** Multi-turn conversations degrade prompt fidelity over time.
2. **Ungrounded Hallucinations:** Agents invent non-existent APIs, violate business constraints, and generate toxic copy without rigid guardrails.
3. **No Cryptographic Provenance:** There is no tamper-proof guarantee that the rules given to an agent match the originator's authoritative baseline.

**OpenPassport solves this at the architectural layer.** It treats business and technical context as compiled, versioned, and cryptographically verified code.

---

## 🏛️ The 7 Canonical Layers

An OpenPassport project organizes all truth into 7 deterministic Markdown layers:

```
docs/passport-context/
├── .gitattributes          # Enforces strict LF (\n) line endings
├── 01-IDENTITY.md          # Core identity: What the entity is and what it is NOT
├── 02-DOCTRINE.md          # Operating axioms, reasoning foundations & anti-slop rules
├── 03-VOICE.md             # Vocabulary whitelist/blacklist & conversational register
├── 04-OFFER.md             # Catalog closure: Deliverables, scope boundaries & pricing
├── 05-GOVERNANCE.md        # Safety precedence, legal boundaries & liability disclaimers
├── 06-CURRENT-STATE.md     # Active metrics and state with strict timestamp (asOf)
├── 07-EVIDENCE.md          # Claims verification & 5-state epistemological audit
├── MASTER-PROMPT.md        # Unified machine prompt with strict precedence rules
├── manifest.json           # Self-sealing manifest with SHA-256 hashes per layer
└── generation.receipt.json # Build receipt with compilation metadata
```

| Layer | Domain | Purpose & Epistemic Rule |
|---|---|---|
| `01-IDENTITY.md` | Core Brand Identity | Definitive boundaries: explicitly defines what the product/founder is and is NOT. |
| `02-DOCTRINE.md` | Epistemic Philosophy | Immutable axioms guiding agent reasoning and rejecting generic hype. |
| `03-VOICE.md` | Tone & Vocabulary | Contrast matrix (*Never Say* vs. *Always Say*); approved and forbidden terms. |
| `04-OFFER.md` | Closed Commercial Catalog | Exact deliverables, currency invariants, scope limits, and refund rules. |
| `05-GOVERNANCE.md` | Authority & Safety | AI disclaimers, escalation gates, human-in-the-loop triggers, liability boundaries. |
| `06-CURRENT-STATE.md` | Operational Reality | Dynamic business status bounded by an explicit cutoff date (`asOf: YYYY-MM-DD`). |
| `07-EVIDENCE.md` | Claims Verification | Every marketing or technical claim classified across 5 epistemological states. |

---

## ⚖️ Mathematical Precedence Hierarchy

When conflicting instructions arise during LLM execution, OpenPassport enforces an invariant decision hierarchy injected into `MASTER-PROMPT.md`:

$$\text{Owner Direct Instruction} > \text{Governance (05)} > \text{Identity / Doctrine (01, 02)} > \text{Offer (04)} > \text{Voice (03)} > \text{Evidence (07)} > \text{Current State (06)} > \text{LLM Prior Knowledge}$$

If an agent is prompted to "recommend a free consultation" but `04-OFFER.md` specifies a closed paid catalog and `05-GOVERNANCE.md` forbids uncompensated work, **the agent fails closed** and respects the governance layer.

---

## 🔒 Cryptographic Integrity Seal

OpenPassport guarantees deterministic reproducibility across all operating systems:
1. **LF Normalization:** Line endings are normalized to LF (`\n`) via `.gitattributes` and internal hasher logic (`CRLF` $\to$ `LF`) before computing hashes.
2. **Per-File Hashes:** Every layer receives a standalone SHA-256 checksum in `manifest.json`.
3. **Self-Sealing Manifest:** To verify the manifest itself without circular dependency, the `sha256` field is set to 64 zeros (`0000000000000000000000000000000000000000000000000000000000000000`), formatted as indented JSON, and then hashed to produce the final cryptographic seal.

---

## 🚀 Quickstart

### 1. Download Binary
Download pre-compiled binaries for Windows, macOS, or Linux from the [Releases page](https://github.com/moshequantum/openpassport/releases).

Or install via Go:
```bash
go install github.com/moshequantum/openpassport/cmd/openpassport@latest
```

### 2. Initialize a Context Package
```bash
openpassport init ./docs/passport-context --name "MyEnterprise" --originator "Founder Name"
```

### 3. Audit & Lint
```bash
openpassport lint ./docs/passport-context
```

### 4. Build & Seal with SHA-256
```bash
openpassport build ./docs/passport-context --fix-crlf
```

### 5. Verify Integrity
```bash
openpassport verify ./docs/passport-context
```

Output:
```
🔒 Verificando integridad criptográfica en: ./docs/passport-context
🎉 [100% PASS] Todos los archivos verificados con hashes SHA-256 e integridad LF determinista.
```

---

## 💻 CLI Reference

| Command | Arguments | Description |
|---|---|---|
| `init` | `[dir] [--name] [--originator]` | Scaffolds the 7 layers, `.gitattributes`, and `MASTER-PROMPT.md`. |
| `lint` | `[dir]` | Audits formatting, CRLF presence, and layer completeness. |
| `build` | `[dir] [--fix-crlf]` | Normalizes content, computes SHA-256 hashes, and seals `manifest.json`. |
| `verify` | `[dir]` | Read-only verification of cryptographic checksums. |
| `export` | `[dir] [--profile] [--out]` | Packages an authenticated profile bundle (`.tar.gz`) for deployment. |
| `version` | — | Displays the current CLI version and standard specification. |

---

## 🤖 Model Context Protocol (MCP)

OpenPassport ships with an official MCP server located in `packages/mcp-passport`. Connect it directly to **Cursor**, **Claude Desktop**, or **Windsurf**:

```json
{
  "mcpServers": {
    "openpassport": {
      "command": "node",
      "args": ["/path/to/openpassport/packages/mcp-passport/dist/cli.js", "--passport", "./docs/passport-context"]
    }
  }
}
```

### Exposed Capabilities:
* **Resources:** `passport://identity`, `passport://doctrine`, `passport://voice`, `passport://offer`, `passport://governance`, `passport://current-state`, `passport://evidence`.
* **Tools:** `verify_passport_integrity`, `get_layer_content`, `check_claim_evidence`.

---

## 📄 License

OpenPassport is open-source software licensed under the **Apache-2.0 License**.

Designed and maintained by **[Multiversa Group LLC](https://multiversa.group)**.
