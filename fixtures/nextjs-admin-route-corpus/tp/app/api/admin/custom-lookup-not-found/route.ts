import { getInviteById } from "@/server/invites";
import { db } from "@/server/db";
import { notFound } from "@/server/http";

export async function DELETE(_request: Request, { params }: { params: { id: string } }) {
  const { invite, error } = await getInviteById(params.id);
  if (error) {
    return notFound();
  }
  await db.invite.delete({ where: { id: invite.id } });
  return Response.json({ ok: true });
}
