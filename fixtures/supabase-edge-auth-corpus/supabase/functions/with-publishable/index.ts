import { withSupabase } from "npm:@supabase/server";

Deno.serve(withSupabase({ auth: "publishable" }, async () => Response.json({ ok: true })));
