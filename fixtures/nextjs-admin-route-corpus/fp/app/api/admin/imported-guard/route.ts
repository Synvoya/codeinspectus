import { requireAdmin } from "@/company/security";

export async function GET() {
  await requireAdmin();
  return Response.json(await loadAdminDashboard());
}
