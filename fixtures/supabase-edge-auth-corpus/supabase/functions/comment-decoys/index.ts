// withSupabase({ auth: "user" }, handler)
const documentation = "supabase.auth.getUser(token); if (error || !data.user) return 401";
Deno.serve(async () => Response.json({ documentation }));
