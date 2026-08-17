import { createSupabaseContext } from "npm:@supabase/server";

async function handler(request: Request) {
  const { data: ctx, error } = await createSupabaseContext(request, { auth: "secret" });
  if (error) return new Response("Unauthorized", { status: 401 });
  return Response.json(await ctx.supabaseAdmin.from("jobs").select());
}

Deno.serve(handler);
