#!/usr/bin/env node
import { runStdioServer } from "./server.js";

let passportDir = process.env.PASSPORT_DIR || "./docs/passport-context";

const args = process.argv.slice(2);
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--passport" && i + 1 < args.length) {
    passportDir = args[i + 1];
    i++;
  } else if (args[i].startsWith("--passport=")) {
    passportDir = args[i].substring("--passport=".length);
  } else if (!args[i].startsWith("-")) {
    passportDir = args[i];
  }
}

runStdioServer(passportDir).catch((err) => {
  console.error("[mcp-passport] Error fatal iniciando servidor MCP:", err);
  process.exit(1);
});
