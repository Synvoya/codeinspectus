const supabase = { auth: { getUser: async () => ({ data: { user: { role: "admin" } } }) } };

export async function GET() {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  if (user.role !== "admin") return new Response("Forbidden", { status: 403 });
  return Response.json(await loadAdminData());
}
