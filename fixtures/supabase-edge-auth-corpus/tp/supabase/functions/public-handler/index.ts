Deno.serve(async (_request) => {
  return new Response(JSON.stringify({ ok: true }));
});
