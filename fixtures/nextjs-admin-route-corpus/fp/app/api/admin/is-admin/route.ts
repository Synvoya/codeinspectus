import { getServerSession } from "next-auth";

export const PATCH = async () => {
  const session = await getServerSession();
  if (!session?.user) {
    return new Response("Unauthorized", { status: 401 });
  }
  const isAdmin = session.user.app_metadata.isAdmin;
  if (
    !isAdmin
  ) {
    return new Response("Forbidden", { status: 403 });
  }
  return Response.json(await updateAdminSettings());
};
