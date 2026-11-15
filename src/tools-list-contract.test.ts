/**
 * The tool list (names, descriptions, input and output JSON Schemas) is the contract every agent reads.
 * A dependency bump once changed it silently (zod 4: dropped `additionalProperties: false`, inlined
 * shared definitions, roughly doubled `tools/list`), so the exact JSON is pinned here. An intended
 * change regenerates the snapshot with `UPDATE_TOOLS_SNAPSHOT=1 npx vitest run src/tools-list-contract.test.ts`
 * and the diff is reviewed like any other contract change.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "./server.js";

const SNAPSHOT = new URL("../fixtures/contract/tools-list.json", import.meta.url);

async function listTools(): Promise<unknown> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await createServer().connect(serverTransport);
  const client = new Client({ name: "tools-list-contract", version: "1.0.0" });
  await client.connect(clientTransport);
  const { tools } = await client.listTools();
  await client.close();
  return tools;
}

describe("tools/list contract", () => {
  test("matches the pinned snapshot", async () => {
    const actual = `${JSON.stringify(await listTools(), null, 2)}\n`;
    if (process.env.UPDATE_TOOLS_SNAPSHOT === "1") writeFileSync(SNAPSHOT, actual);
    expect(actual).toBe(readFileSync(SNAPSHOT, "utf8"));
  });
});
