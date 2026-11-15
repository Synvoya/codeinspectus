import Fastify from "fastify";

const server = Fastify();

server.post("/import", async (request, reply) => {
  try {
    await Promise.resolve(request.body);
  } catch (error) {
    request.log.error(error);
    return reply.status(400).send({ error: "The import could not be read" });
  }
  return reply.send({ ok: true });
});
