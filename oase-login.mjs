// One-shot Promise login for oase-mcp: drives promise_login_start/finish
// over MCP stdio, so no Claude session is needed.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const transport = new StdioClientTransport({
  command: "node",
  args: [process.env.HOME + "/oase-mcp/dist/index.js"],
});
const client = new Client({ name: "login-helper", version: "0.0.1" });
await client.connect(transport);

const start = await client.callTool({ name: "promise_login_start", arguments: {} });
console.log("START:", start.content.map((c) => c.text).join("\n"));

const fin = await client.callTool(
  { name: "promise_login_finish", arguments: {} },
  undefined,
  { timeout: 300_000 },
);
console.log("FINISH:", fin.content.map((c) => c.text).join("\n"));

await client.close();
process.exit(fin.isError ? 1 : 0);
