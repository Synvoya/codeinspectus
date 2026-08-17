export async function GET() {
  const bounded = ((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((true))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))));
  if (!bounded) return new Response("Unauthorized", { status: 401 });
  return Response.json(await loadBoundedAdminData());
}
