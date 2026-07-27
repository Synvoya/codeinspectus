Deno.serve(async (request) => {
  const authorization = request.headers.get("Authorization");
  const { data, error } = await supabase.auth.getUser(authorization ?? "");
  if (error || !data.user) return new Response("Unauthorized", { status: 401 });
  return new Response(JSON.stringify({ userId: data.user.id }));
});

declare const supabase: {
  auth: {
    getUser(token: string): Promise<{
      data: { user?: { id: string } };
      error?: unknown;
    }>;
  };
};
