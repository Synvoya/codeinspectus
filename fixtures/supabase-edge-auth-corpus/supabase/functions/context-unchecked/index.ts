import { createSupabaseContext } from "npm:@supabase/server";

Deno.serve(async (request) => {
  const result = await createSupabaseContext(request, { auth: "user" });
  return Response.json({ context: result.data });
});
