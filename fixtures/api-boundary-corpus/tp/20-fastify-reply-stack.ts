import Fastify from "fastify";

declare function rebuildIndex(): Promise<void>;

const server = Fastify();

server.post("/reindex", async (request, reply) => {
  try {
    await rebuildIndex();
  } catch (err: any) {
    return reply.send({ error: err.stack });
  }
});
