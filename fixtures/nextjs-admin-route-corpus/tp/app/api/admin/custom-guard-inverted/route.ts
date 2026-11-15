import { readSession } from "@/server/session";
import { mayManageMembers } from "@/server/policy";
import { db } from "@/server/db";

export async function DELETE(request: Request) {
  const { error } = await readSession(request);
  if (!error) {
    return Response.json({ skipped: true });
  }
  await db.member.deleteMany({ where: { stale: true } });
  return Response.json({ ok: true });
}

export async function POST(request: Request) {
  if (await mayManageMembers(request)) {
    return Response.json({ error: "forbidden" }, { status: 403 });
  }
  await db.member.create({ data: { invitedBy: "admin" } });
  return Response.json({ ok: true });
}
