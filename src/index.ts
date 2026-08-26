#!/usr/bin/env node
/**
 * MCP entry point — `node dist/index.js` starts the stdio MCP server
 * (`claude mcp add oase -- node /path/to/dist/index.js`). The
 * implementation lives in ./mcp/server.js, built on the passive client
 * layer in ./client — which is also importable on its own
 * (`import { OaseClient } from "oase-mcp"`).
 */
import { runMcpServer } from "./mcp/server.js";

runMcpServer().catch((e) => {
  console.error("[oase-mcp] fatal:", e);
  process.exit(1);
});
