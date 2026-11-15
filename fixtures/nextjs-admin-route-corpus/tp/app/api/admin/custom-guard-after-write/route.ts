import { readSession } from "@/server/session";
import { db } from "@/server/db";

export async function DELETE(request: Request) {
  await db.member.deleteMany({ where: { stale: true } });
  const { error } = await readSession(request);
  if (error) {
    return error.toResponse();
  }
  return Response.json({ ok: true });
}
