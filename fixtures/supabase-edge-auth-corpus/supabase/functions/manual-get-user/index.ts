import { createClient } from "npm:@supabase/supabase-js";

const supabase = createClient("https://example.supabase.co", "publishable-key");
Deno.serve(async (request) => {
  const { data, error } = await supabase.auth.getUser(request.headers.get("Authorization") ?? "");
  if (error || !data.user) return new Response("Unauthorized", { status: 401 });
  return Response.json({ userId: data.user.id });
});
