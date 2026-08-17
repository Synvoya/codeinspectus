import { createClient } from "@supabase/supabase-js";

export async function DELETE() {
  const supabase = createClient("https://example.supabase.co", "publishable-key");
  const providerAuth = supabase.auth;
  function poison() {
    providerAuth.getUser = async () => ({ data: { user: null } });
  }
  process.env.POISON && poison?.();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  if (user.app_metadata.role !== "admin") return new Response("Forbidden", { status: 403 });
  return Response.json(await deleteAdminData());
}
