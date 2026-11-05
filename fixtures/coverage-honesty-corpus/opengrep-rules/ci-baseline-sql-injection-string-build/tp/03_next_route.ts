export async function POST(request: Request) {
  const body = await request.json();
  return Response.json(await sql.query(`DELETE FROM items WHERE id = ${body.id}`));
}
