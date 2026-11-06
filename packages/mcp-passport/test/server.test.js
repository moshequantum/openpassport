import { describe, it } from "node:test";
import assert from "node:assert";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { createPassportMcpServer } from "../dist/server.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const templateDir = path.resolve(__dirname, "../../../templates/open-passport-template");

describe("@multiversa/mcp-passport", () => {
  async function setupClient(dir = templateDir) {
    const server = createPassportMcpServer({ passportDir: dir });
    const client = new Client(
      { name: "test-client", version: "1.0.0" },
      { capabilities: {} }
    );
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([
      server.connect(serverTransport),
      client.connect(clientTransport),
    ]);
    return { client, server };
  }

  it("lists canonical resources including passport://current-state (B6)", async () => {
    const { client } = await setupClient();
    const { resources } = await client.listResources();
    const uris = resources.map((r) => r.uri);
    assert.ok(uris.includes("passport://identity"), "missing passport://identity");
    assert.ok(uris.includes("passport://current-state"), "missing passport://current-state");
    assert.ok(uris.includes("passport://evidence"), "missing passport://evidence");
  });

  it("lists required tools including get_layer_content and check_claim_evidence (B6)", async () => {
    const { client } = await setupClient();
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);
    assert.ok(names.includes("get_layer_content"), "missing get_layer_content");
    assert.ok(names.includes("check_claim_evidence"), "missing check_claim_evidence");
    assert.ok(names.includes("resolve_context"), "missing resolve_context");
    assert.ok(names.includes("verify_passport_integrity"), "missing verify_passport_integrity");
  });

  it("get_layer_content reads canonical layer content correctly", async () => {
    const { client } = await setupClient();
    const res = await client.callTool({
      name: "get_layer_content",
      arguments: { layer: "identity" },
    });
    assert.strictEqual(res.isError, undefined);
    assert.ok(res.content[0].text.includes("01-IDENTITY.md"));
  });

  it("check_claim_evidence queries evidence layer", async () => {
    const { client } = await setupClient();
    const res = await client.callTool({
      name: "check_claim_evidence",
      arguments: { claim: "System is 100% deterministic" },
    });
    assert.strictEqual(res.isError, undefined);
    assert.ok(res.content[0].text.includes("07-EVIDENCE.md"));
  });

  it("resolve_context is FAIL-CLOSED on invalid or missing profile (H1)", async () => {
    const { client } = await setupClient();
    const res = await client.callTool({
      name: "resolve_context",
      arguments: { profile: "non-existent-profile" },
    });
    assert.strictEqual(res.isError, true, "Expected error on non-existent profile");
    assert.ok(res.content[0].text.includes("Fail-Closed"));
  });

  it("resolve_context on valid public profile does not leak private layers (H1)", async () => {
    const { client } = await setupClient();
    const res = await client.callTool({
      name: "resolve_context",
      arguments: { profile: "core-public" },
    });
    assert.strictEqual(res.isError, undefined);
    assert.ok(res.content[0].text.includes("01-IDENTITY.md"));
    // Governance and Current State are private in template, verify they are not exposed in core-public
    assert.strictEqual(res.content[0].text.includes("05-GOVERNANCE.md"), false);
  });
});
