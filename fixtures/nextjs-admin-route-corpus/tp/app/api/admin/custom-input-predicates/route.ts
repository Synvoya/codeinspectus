import { hasRequiredFields, isFileTypeAllowed } from "@/server/validation";
import { db } from "@/server/db";
import { badRequest } from "@/server/http";

export async function POST(request: Request) {
  const body = await request.json();
  if (!hasRequiredFields(body)) return badRequest();
  await db.user.create({ data: { email: String(body.email), role: "member" } });
  return Response.json({ ok: true });
}

export async function PUT(request: Request) {
  const form = await request.formData();
  if (!(await isFileTypeAllowed(form.get("file")))) return badRequest();
  await db.upload.create({ data: { name: String(form.get("name")) } });
  return Response.json({ ok: true });
}
