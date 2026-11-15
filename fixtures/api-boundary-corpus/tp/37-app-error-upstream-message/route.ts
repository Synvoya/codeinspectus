import { ProviderRejectedError } from "./errors";
import { sendViaProvider } from "./client";

export async function POST(request: Request) {
  try {
    await sendViaProvider(await request.text());
    return Response.json({ ok: true });
  } catch (err) {
    if (err instanceof ProviderRejectedError) return Response.json({ error: err.message }, { status: 502 });
    return Response.json({ error: "Send failed" }, { status: 500 });
  }
}
