import { requireAdmin } from "@company/security";

export async function GET() {
  const response = await loadAdminData();
  await requireAdmin();
  return Response.json(response);
}
