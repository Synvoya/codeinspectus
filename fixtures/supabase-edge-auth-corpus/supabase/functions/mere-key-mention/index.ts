Deno.serve(async () => {
  const keyName = "service_role";
  const configured = Boolean(Deno.env.get("SUPABASE_SECRET_KEY"));
  return Response.json({ keyName, configured });
});
