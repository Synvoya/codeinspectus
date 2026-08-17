import { createClient } from "@supabase/supabase-js";

export async function POST() {
  const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_PUBLISHABLE_KEY!);
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  if (user.user_metadata.role !== "admin") return new Response("Forbidden", { status: 403 });
  return Response.json(await updateBilling());
}
