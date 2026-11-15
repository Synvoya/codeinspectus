import { readSession } from "@/server/session";
import { db } from "@/server/db";

export async function DELETE(request: Request) {
  const { session, error } = await readSession(request);
  if (error) console.warn("session could not be read", error);
  await db.member.delete({ where: { id: session?.memberId } });
  return Response.json({ ok: true });
}
