#!/usr/bin/env node
import { runStdioServer } from "./server.js";

const passportDir = process.argv[2] || process.env.PASSPORT_DIR || "./docs/passport-context";

runStdioServer(passportDir).catch((err) => {
  console.error("[mcp-passport] Error fatal iniciando servidor MCP:", err);
  process.exit(1);
});
