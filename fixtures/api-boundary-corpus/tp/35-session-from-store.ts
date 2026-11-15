declare const env: { DB: unknown };
declare function loadSession(env: unknown, userId: string): Promise<string>;

export async function GET(request: Request) {
  const token = await loadSession(env, new URL(request.url).searchParams.get("user") ?? "");
  return Response.json({ token });
}
