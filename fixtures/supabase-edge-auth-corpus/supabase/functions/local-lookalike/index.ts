function withSupabase(_options: unknown, handler: () => Response) {
  return handler;
}

Deno.serve(withSupabase({ auth: "user" }, () => Response.json({ ok: true })));
