/**
 * MCP clients run in another working directory than the server. An empty or relative `path` used to
 * resolve against the server's cwd and silently scan the wrong directory; every path-taking tool now
 * rejects it before any work starts.
 */
import { describe, expect, test } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "./server.js";

async function connectedClient(): Promise<Client> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await createServer().connect(serverTransport);
  const client = new Client({ name: "path-input-test", version: "1.0.0" });
  await client.connect(clientTransport);
  return client;
}

describe("MCP path inputs", () => {
  test.each([
    ["codeinspectus_scan", {}],
    ["codeinspectus_rescan", {}],
    ["codeinspectus_generate_sbom", {}],
    ["codeinspectus_plan_cleanup", { artifact_ids: ["artifact-x"] }],
  ])("%s rejects empty and relative paths", async (name, extra) => {
    const client = await connectedClient();
    for (const path of ["", ".", "src", "../elsewhere"]) {
      const result = await client.callTool({ name, arguments: { path, ...extra } }).catch((error: Error) => ({ isError: true, content: [{ type: "text", text: error.message }] }));
      expect(result.isError, `${name} ${JSON.stringify(path)}`).toBe(true);
      expect(JSON.stringify(result.content)).toMatch(/absolute path|too_small|at least 1/i);
    }
    await client.close();
  });
});
