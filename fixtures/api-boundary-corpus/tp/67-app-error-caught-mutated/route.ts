class RateLimitedError extends Error {}

async function callProvider(): Promise<void> {
  const response = await fetch("https://provider.invalid/v1/items");
  if (response.status === 429) throw new RateLimitedError("Too many requests");
}

async function withContext(cause: string): Promise<void> {
  try {
    await callProvider();
  } catch (err) {
    if (err instanceof RateLimitedError) err.message = `${err.message}: ${cause}`;
    throw err;
  }
}

export async function GET(request: Request) {
  try {
    await withContext(new URL(request.url).searchParams.get("trace") ?? "");
    return Response.json({ ok: true });
  } catch (err) {
    if (err instanceof RateLimitedError) return Response.json({ error: err.message }, { status: 429 });
    return Response.json({ error: "Request failed" }, { status: 500 });
  }
}
