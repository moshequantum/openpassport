import fs from "node:fs";
import path from "node:path";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { verifyPassportIntegrity, PassportManifest } from "@multiversa/passport-core";

export interface McpServerConfig {
  passportDir: string;
}

export function createPassportMcpServer(config: McpServerConfig) {
  const passportDir = path.resolve(config.passportDir);

  const server = new Server(
    {
      name: "multiversa/mcp-passport",
      version: "1.0.0",
    },
    {
      capabilities: {
        tools: {},
        resources: {},
      },
    }
  );

  // Helper to read file safely
  function readLayerFile(fileName: string): string | null {
    const full = path.join(passportDir, fileName);
    if (!fs.existsSync(full)) return null;
    return fs.readFileSync(full, "utf8");
  }

  // 1. List Resources
  server.setRequestHandler(ListResourcesRequestSchema, async () => {
    return {
      resources: [
        {
          uri: "passport://identity",
          name: "01-IDENTITY.md",
          description: "Identidad estable, pilares, qué es y qué NO es",
          mimeType: "text/markdown",
        },
        {
          uri: "passport://doctrine",
          name: "02-DOCTRINE.md",
          description: "Axiomas innegociables, principios y militancia anti-slop",
          mimeType: "text/markdown",
        },
        {
          uri: "passport://voice",
          name: "03-VOICE.md",
          description: "Matriz de contraste, whitelist de autor y palabras tabú",
          mimeType: "text/markdown",
        },
        {
          uri: "passport://offer",
          name: "04-OFFER.md",
          description: "Catálogo cerrado de entregables con límites estrictos",
          mimeType: "text/markdown",
        },
        {
          uri: "passport://governance",
          name: "05-GOVERNANCE.md",
          description: "Reparto de autoridad, deslindes legales e invariante de privacidad",
          mimeType: "text/markdown",
        },
        {
          uri: "passport://current-state",
          name: "06-CURRENT-STATE.md",
          description: "Invariante temporal con fecha de corte estricta (asOf)",
          mimeType: "text/markdown",
        },
        {
          uri: "passport://state",
          name: "06-CURRENT-STATE.md",
          description: "Invariante temporal (alias)",
          mimeType: "text/markdown",
        },
        {
          uri: "passport://evidence",
          name: "07-EVIDENCE.md",
          description: "Clasificación epistemológica en 5 niveles de certeza",
          mimeType: "text/markdown",
        },
        {
          uri: "passport://manifest",
          name: "manifest.json",
          description: "Manifiesto criptográfico determinista OpenPassport v1.0",
          mimeType: "application/json",
        },
        {
          uri: "passport://master-prompt",
          name: "MASTER-PROMPT.md",
          description: "Prompt intérprete de IA con fórmula matemática de precedencia",
          mimeType: "text/markdown",
        },
      ],
    };
  });

  // 2. Read Resource
  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const uri = request.params.uri;
    const layerMap: Record<string, string> = {
      "passport://identity": "01-IDENTITY.md",
      "passport://doctrine": "02-DOCTRINE.md",
      "passport://voice": "03-VOICE.md",
      "passport://offer": "04-OFFER.md",
      "passport://governance": "05-GOVERNANCE.md",
      "passport://current-state": "06-CURRENT-STATE.md",
      "passport://state": "06-CURRENT-STATE.md",
      "passport://evidence": "07-EVIDENCE.md",
      "passport://manifest": "manifest.json",
      "passport://master-prompt": "MASTER-PROMPT.md",
    };

    const fileName = layerMap[uri];
    if (!fileName) {
      throw new Error(`Recurso no reconocido: ${uri}`);
    }

    const content = readLayerFile(fileName);
    if (content === null) {
      throw new Error(`El archivo ${fileName} no existe en ${passportDir}`);
    }

    return {
      contents: [
        {
          uri,
          mimeType: fileName.endsWith(".json") ? "application/json" : "text/markdown",
          text: content,
        },
      ],
    };
  });

  // 3. List Tools
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: [
        {
          name: "get_passport_manifest",
          description: "Obtiene el manifiesto criptográfico y los metadatos de OpenPassport v1.0.",
          inputSchema: {
            type: "object",
            properties: {},
          },
        },
        {
          name: "get_passport_layer",
          description: "Recupera una capa semántica específica del pasaporte.",
          inputSchema: {
            type: "object",
            properties: {
              layer: {
                type: "string",
                description: "Nombre de capa: identity, doctrine, voice, offer, governance, state, evidence, master-prompt",
              },
            },
            required: ["layer"],
          },
        },
        {
          name: "get_layer_content",
          description: "Alias de get_passport_layer: Recupera el contenido textual de una capa canónica.",
          inputSchema: {
            type: "object",
            properties: {
              layer: {
                type: "string",
                description: "Nombre de capa: identity, doctrine, voice, offer, governance, state, evidence, master-prompt",
              },
            },
            required: ["layer"],
          },
        },
        {
          name: "check_claim_evidence",
          description: "Contrasta una afirmación o hecho contra las evidencias epistémicas de la capa 07-EVIDENCE.md.",
          inputSchema: {
            type: "object",
            properties: {
              claim: {
                type: "string",
                description: "Afirmación a verificar con evidencia epistémica.",
              },
            },
            required: ["claim"],
          },
        },
        {
          name: "resolve_context",
          description: "Resuelve y consolida el contexto bajo la estricta jerarquía de precedencia matemática (Fail-Closed).",
          inputSchema: {
            type: "object",
            properties: {
              profile: {
                type: "string",
                description: "Perfil de exportación (ej. core-public, operational-private, full)",
                default: "core-public",
              },
            },
          },
        },
        {
          name: "verify_passport_integrity",
          description: "Audita la integridad criptográfica SHA-256 y normalización LF del pasaporte.",
          inputSchema: {
            type: "object",
            properties: {},
          },
        },
      ],
    };
  });

  // 4. Handle Tools
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    switch (name) {
      case "get_passport_manifest": {
        const content = readLayerFile("manifest.json");
        if (!content) {
          return { content: [{ type: "text", text: "Error: manifest.json no encontrado." }], isError: true };
        }
        return { content: [{ type: "text", text: content }] };
      }

      case "get_layer_content":
      case "get_passport_layer": {
        const layerKey = String((args as Record<string, unknown>)?.layer || "").toLowerCase();
        const map: Record<string, string> = {
          identity: "01-IDENTITY.md",
          doctrine: "02-DOCTRINE.md",
          voice: "03-VOICE.md",
          offer: "04-OFFER.md",
          governance: "05-GOVERNANCE.md",
          state: "06-CURRENT-STATE.md",
          "current-state": "06-CURRENT-STATE.md",
          evidence: "07-EVIDENCE.md",
          "master-prompt": "MASTER-PROMPT.md",
        };
        const fileName = map[layerKey];
        if (!fileName) {
          return { content: [{ type: "text", text: `Capa no válida: ${layerKey}` }], isError: true };
        }
        const text = readLayerFile(fileName);
        if (!text) {
          return { content: [{ type: "text", text: `Archivo ${fileName} no encontrado.` }], isError: true };
        }
        return { content: [{ type: "text", text }] };
      }

      case "check_claim_evidence": {
        const claim = String((args as Record<string, unknown>)?.claim || "").trim();
        const evidenceContent = readLayerFile("07-EVIDENCE.md");
        if (!evidenceContent) {
          return { content: [{ type: "text", text: "Error: 07-EVIDENCE.md no encontrado en el pasaporte." }], isError: true };
        }
        return {
          content: [
            {
              type: "text",
              text: `# AUDITORÍA DE EVIDENCIA EPISTÉMICA\n\n**Afirmación a Contrastar:**\n> "${claim}"\n\n**Evidencia Canónica (07-EVIDENCE.md):**\n\n${evidenceContent}`,
            },
          ],
        };
      }

      case "resolve_context": {
        // FAIL-CLOSED: Validates manifest and profile presence strictly
        const profileId = String((args as Record<string, unknown>)?.profile || "core-public").toLowerCase();
        const manifestRaw = readLayerFile("manifest.json");
        if (!manifestRaw) {
          return {
            content: [{ type: "text", text: "Error de seguridad (Fail-Closed): manifest.json no encontrado." }],
            isError: true,
          };
        }

        let parsedManifest: PassportManifest;
        try {
          parsedManifest = JSON.parse(manifestRaw);
        } catch (err) {
          return {
            content: [{ type: "text", text: `Error de seguridad (Fail-Closed): manifest.json corrupto o inválido: ${String(err)}` }],
            isError: true,
          };
        }

        const targetProfile = parsedManifest.profiles?.find((p) => p.id.toLowerCase() === profileId);
        if (!targetProfile) {
          return {
            content: [{ type: "text", text: `Error de seguridad (Fail-Closed): perfil '${profileId}' no existe en manifest.json.` }],
            isError: true,
          };
        }

        const isPublicProfile = profileId.includes("public");
        const allowedFiles = new Set<string>();

        for (const fileEntry of parsedManifest.files || []) {
          if (targetProfile.files.includes(fileEntry.path)) {
            // Strict visibility invariant: public profiles NEVER receive non-public files
            if (isPublicProfile && fileEntry.visibility !== "public") {
              continue;
            }
            allowedFiles.add(fileEntry.path);
          }
        }

        if (targetProfile.files.includes("MASTER-PROMPT.md")) {
          allowedFiles.add("MASTER-PROMPT.md");
        }

        const precedenceOrder = [
          "MASTER-PROMPT.md",
          "05-GOVERNANCE.md",
          "01-IDENTITY.md",
          "02-DOCTRINE.md",
          "04-OFFER.md",
          "03-VOICE.md",
          "07-EVIDENCE.md",
          "06-CURRENT-STATE.md",
        ];

        let consolidated = `# CONTEXTO RESUELTO BAJO JERARQUÍA DE PRECEDENCIA (OPENPASSPORT v1.0)\n\n`;
        consolidated += `> Perfil Activo: ${profileId}\n`;
        consolidated += `> Fórmula de Precedencia: Titular > Gobernanza (05) > Identidad/Doctrina (01,02) > Oferta (04) > Voz (03) > Evidencia (07) > Estado (06)\n\n---\n\n`;

        for (const l of precedenceOrder) {
          if (!allowedFiles.has(l)) {
            continue;
          }
          const content = readLayerFile(l);
          if (content) {
            consolidated += `\n<!-- INICIO DE CAPA: ${l} -->\n${content}\n<!-- FIN DE CAPA: ${l} -->\n\n---\n`;
          }
        }

        return { content: [{ type: "text", text: consolidated }] };
      }

      case "verify_passport_integrity": {
        const audit = verifyPassportIntegrity(passportDir);
        const summary = {
          valid: audit.valid,
          hasGitAttributes: audit.hasGitAttributes,
          hasCRLF: audit.hasCRLF,
          selfHashMatches: audit.selfHashMatches,
          computedSelfHash: audit.computedSelfHash,
          errors: audit.errors,
        };
        return { content: [{ type: "text", text: JSON.stringify(summary, null, 2) }] };
      }

      default:
        throw new Error(`Herramienta no implementada: ${name}`);
    }
  });

  return server;
}

export async function runStdioServer(passportDir: string = ".") {
  const server = createPassportMcpServer({ passportDir });
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`[mcp-passport] Servidor MCP iniciado sobre stdio para: ${passportDir}`);
}
