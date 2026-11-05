// Next.js App Router: query-string input read through new URL(request.url).
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const q = searchParams.get("q");
  return Response.json(await db.query("SELECT * FROM t WHERE name = '" + q + "'"));
}
