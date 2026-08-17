import { createClient } from "npm:@supabase/supabase-js";

const supabase = createClient("https://example.supabase.co", "publishable-key");
Deno.serve(async (request) => {
  const result = await supabase.auth.getUser(request.headers.get("Authorization") ?? "");
  return Response.json({ user: result.data.user });
});
