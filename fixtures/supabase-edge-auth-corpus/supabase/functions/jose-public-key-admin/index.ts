import { jwtVerify } from "npm:jose";
import { createClient } from "npm:@supabase/supabase-js";

const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SECRET_KEY")!);

Deno.serve(async (request) => {
  try {
    await jwtVerify(request.headers.get("Authorization") ?? "", new Uint8Array(32));
  } catch {
    return new Response("Unauthorized", { status: 401 });
  }
  return Response.json(await admin.from("accounts").select());
});
