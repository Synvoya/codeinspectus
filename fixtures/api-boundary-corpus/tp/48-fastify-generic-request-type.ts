import type { FastifyReply, FastifyRequest } from "fastify-types-only";

declare function renameFolder(id: string, name: string): Promise<void>;

export async function renameHandler(
  request: FastifyRequest<{ Params: { id: string }; Body: { name: string } }, unknown>,
  reply: FastifyReply,
) {
  try {
    await renameFolder(request.params.id, request.body.name);
  } catch (error: any) {
    return reply.send({ error: error.message });
  }
}
