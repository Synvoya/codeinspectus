import { parseBody } from "@/server/body";
import { db } from "@/server/db";
import { badRequest } from "@/server/http";

export async function PATCH(request: Request) {
  const { body, error } = await parseBody(request);
  if (error) return badRequest(error);
  await db.user.update({ where: { id: body.id }, data: { role: body.role } });
  return Response.json({ ok: true });
}
