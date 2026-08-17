Deno.serve(async (request) => {
  const authorization = request.headers.get("Authorization");
  return Response.json({ authorizationPresent: Boolean(authorization) });
});
