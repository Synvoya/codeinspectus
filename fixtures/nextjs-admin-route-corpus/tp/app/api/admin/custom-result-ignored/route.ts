import { readSession } from "@/server/session";
import { db } from "@/server/db";

export async function DELETE(request: Request) {
  const { session } = await readSession(request);
  await db.member.delete({ where: { id: session?.memberId } });
  return Response.json({ ok: true });
}
