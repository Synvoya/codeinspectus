import { auth } from "@clerk/nextjs/server";

export async function DELETE() {
  await auth.protect({ permission: "org:team_settings:manage" });
  return Response.json(await deleteAdminData());
}
