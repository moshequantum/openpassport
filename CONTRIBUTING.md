# Contributing to OpenPassport

Thank you for contributing to OpenPassport! We welcome pull requests, bug reports, and architectural feedback.

## Development Workflow

### Prerequisites
- **Go**: 1.22+ (tested on Go 1.27)
- **Node.js**: 20+
- **pnpm**: 9+ (or 11+)

### Building and Testing

1. **Go CLI & Core:**
   ```bash
   go test -race ./...
   go build ./...
   ```

2. **TypeScript Packages:**
   ```bash
   pnpm install
   pnpm -r build
   pnpm -r test
   pnpm audit --prod
   ```

3. **Verifying Canonical Templates:**
   ```bash
   go run ./cmd/openpassport verify templates/open-passport-template
   ```

## Ground Rules

- **Deterministic Builds**: Every file hash must use LF line endings and UTF-8 encoding.
- **Fail-Closed MCP**: MCP endpoints must reject missing or unverified context profiles.
- **Security First**: Path traversal (`..`) is strictly prohibited in file entries and bundle extraction.
- **License**: All contributions fall under the [Apache-2.0 License](LICENSE).
