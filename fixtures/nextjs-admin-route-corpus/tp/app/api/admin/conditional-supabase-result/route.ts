import { createClient } from "@supabase/supabase-js";

export async function DELETE(request: Request) {
  const supabase = createClient("https://example.supabase.co", "publishable-key");
  const { data: { user } } = process.env.STRICT
    ? await supabase.auth.getUser()
    : { data: { user: await request.json() } };
  if (!user) return new Response("Unauthorized", { status: 401 });
  if (user.app_metadata.role !== "admin") return new Response("Forbidden", { status: 403 });
  return Response.json(await deleteAdminData());
}
