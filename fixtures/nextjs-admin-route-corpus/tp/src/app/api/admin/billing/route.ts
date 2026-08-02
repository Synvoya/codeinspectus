import { createClient } from "@/lib/supabase/server";

export async function POST() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  if (user.user_metadata.role !== "admin") return new Response("Forbidden", { status: 403 });
  return Response.json(await updateBilling());
}
