import { GatewayRejectedError } from "./errors";

async function forward(body: string): Promise<void> {
  const response = await fetch("https://gateway.invalid/forward", { method: "POST", body });
  if (!response.ok) throw new GatewayRejectedError(await response.text());
}

export async function POST(request: Request) {
  try {
    await forward(await request.text());
    return Response.json({ ok: true });
  } catch (err) {
    if (err instanceof GatewayRejectedError) return Response.json({ error: err.message }, { status: 502 });
    return Response.json({ error: "Forward failed" }, { status: 500 });
  }
}
