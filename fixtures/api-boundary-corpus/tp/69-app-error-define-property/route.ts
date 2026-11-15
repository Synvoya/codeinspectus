class SyncConflictError extends Error {}

function conflict(detail: string): SyncConflictError {
  const e = new SyncConflictError("The record changed on the server");
  Object.defineProperty(e, "message", { value: detail });
  return e;
}

export async function PUT(request: Request) {
  try {
    const response = await fetch("https://sync.invalid/push", { method: "PUT", body: await request.text() });
    if (response.status === 409) throw conflict(await response.text());
    return Response.json({ ok: true });
  } catch (err) {
    if (err instanceof SyncConflictError) return Response.json({ error: err.message }, { status: 409 });
    return Response.json({ error: "Sync failed" }, { status: 500 });
  }
}
