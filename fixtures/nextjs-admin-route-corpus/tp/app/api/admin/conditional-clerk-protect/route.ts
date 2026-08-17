import { auth } from "@clerk/nextjs/server";

export async function DELETE() {
  process.env.CHECK_AUTH === "true" &&
    await auth.protect({ permission: "org:team_settings:manage" });
  return Response.json(await deleteAdminData());
}
