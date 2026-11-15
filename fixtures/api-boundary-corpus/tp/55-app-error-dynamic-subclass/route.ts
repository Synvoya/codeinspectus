import { ProviderQuotaError, QuotaError } from "./errors";

async function send(body: string): Promise<void> {
  const response = await fetch("https://provider.invalid/send", { method: "POST", body });
  if (response.status === 429) throw new ProviderQuotaError(await response.text());
}

export async function POST(request: Request) {
  try {
    await send(await request.text());
    return Response.json({ ok: true });
  } catch (err) {
    if (err instanceof QuotaError) return Response.json({ error: err.message }, { status: 429 });
    return Response.json({ error: "Send failed" }, { status: 500 });
  }
}
