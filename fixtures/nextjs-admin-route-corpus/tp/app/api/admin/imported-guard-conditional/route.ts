import { requireAdmin } from "@company/security";

export async function GET() {
  if (process.env.CHECK_AUTH === "true") await requireAdmin();
  return Response.json(await loadAdminData());
}
