import { createClient } from "npm:@supabase/supabase-js";

const supabase = createClient("https://example.supabase.co", "publishable-key");
async function authenticate(token: string) {
  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data.user) return undefined;
  return data.user;
}

Deno.serve(async () => Response.json({ ok: true }));
