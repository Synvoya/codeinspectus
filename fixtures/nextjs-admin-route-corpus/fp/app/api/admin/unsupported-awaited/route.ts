export async function GET(request: Request) {
  const parsed = await parseRequest(request);
  const theme = await fetchTheme();
  return Response.json({ parsed, theme });
}
