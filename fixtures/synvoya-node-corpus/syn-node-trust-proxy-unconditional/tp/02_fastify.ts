import Fastify from "fastify";
export const server = Fastify({ logger: true, trustProxy: true });
