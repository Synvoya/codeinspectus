import { Hono } from "hono";

declare function syncFeeds(): Promise<number>;

const app = new Hono();

app.post("/sync", async (c) => {
  try {
    return c.json({ synced: await syncFeeds() });
  } catch (e) {
    return c.json({ error: e instanceof Error ? e.message : "sync failed" }, 500);
  }
});

export default app;
