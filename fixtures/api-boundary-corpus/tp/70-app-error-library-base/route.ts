import * as lib from "some-http-lib";

class UpstreamFailedError extends lib.Error {
  constructor() {
    super("Upstream failed");
  }
}

async function callUpstream(): Promise<void> {
  const response = await fetch("https://upstream.invalid/run", { method: "POST" });
  if (!response.ok) throw new UpstreamFailedError();
}

export async function POST() {
  try {
    await callUpstream();
    return Response.json({ ok: true });
  } catch (err) {
    if (err instanceof UpstreamFailedError) return Response.json({ error: err.message }, { status: 502 });
    return Response.json({ error: "Run failed" }, { status: 500 });
  }
}
