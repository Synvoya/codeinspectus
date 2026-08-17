export async function GET() {
  return Response.json(await loadMalformedAdminData());
