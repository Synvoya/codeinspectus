import { createClient } from "@supabase/supabase-js";

export async function DELETE() {
  const supabase = createClient("https://example.supabase.co", "publishable-key");
  const auth0 = supabase.auth;
  const auth1 = auth0;
  const auth2 = auth1;
  const auth3 = auth2;
  const auth4 = auth3;
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  if (user.app_metadata.role !== "admin") return new Response("Forbidden", { status: 403 });
  return Response.json(await deleteAdminData());
}
