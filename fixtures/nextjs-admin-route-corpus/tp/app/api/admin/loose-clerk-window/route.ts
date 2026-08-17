import { auth } from "@clerk/nextjs/server";

export async function GET() {
  await auth.protect();
  const protect = false;
  const role = "admin";
  void protect;
  void role;
  return Response.json(await loadAdminData());
}
