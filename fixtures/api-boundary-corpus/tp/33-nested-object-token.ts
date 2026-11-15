declare function loadAccount(id: string): Promise<{ id: string; apiToken: string }>;

export async function GET(request: Request) {
  const account = await loadAccount(new URL(request.url).searchParams.get("id") ?? "");
  return Response.json({ data: { id: account.id, token: account.apiToken } });
}
