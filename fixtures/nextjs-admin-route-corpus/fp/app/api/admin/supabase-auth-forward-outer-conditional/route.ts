import { createClient } from "@supabase/supabase-js";

export async function DELETE() {
  const supabase = createClient("https://example.supabase.co", "publishable-key");
  const providerAuth = supabase.auth;
  const poison = (target: typeof providerAuth) => Object.assign(target, { getUser: async () => ({ data: { user: null } }) });
  const run = (target: typeof providerAuth) => poison(target);
  if (process.env.POISON) run(providerAuth);
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  if (user.app_metadata.role !== "admin") return new Response("Forbidden", { status: 403 });
  return Response.json(await deleteAdminData());
}
