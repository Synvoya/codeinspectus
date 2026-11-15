class LimitReachedError extends Error {}

function limitError(detail: string): LimitReachedError {
  const e = new LimitReachedError("The limit was reached");
  Object.assign(e, { message: detail });
  return e;
}

export async function POST(request: Request) {
  try {
    const response = await fetch("https://quota.invalid/check", { method: "POST", body: await request.text() });
    if (!response.ok) throw limitError(await response.text());
    return Response.json({ ok: true });
  } catch (err) {
    if (err instanceof LimitReachedError) return Response.json({ error: err.message }, { status: 429 });
    return Response.json({ error: "Check failed" }, { status: 500 });
  }
}
