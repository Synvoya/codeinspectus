import { ShareLimitError } from "./errors";
import "./lib/detail";

declare module "./errors" {
  interface ShareLimitError {
    withDetail(detail: string): ShareLimitError;
  }
}

export async function POST(request: Request) {
  try {
    const response = await fetch("https://share.invalid/links", { method: "POST", body: await request.text() });
    if (response.status === 429) throw new ShareLimitError().withDetail(await response.text());
    return Response.json({ ok: true });
  } catch (err) {
    if (err instanceof ShareLimitError) return Response.json({ error: err.message }, { status: 429 });
    return Response.json({ error: "Could not share" }, { status: 500 });
  }
}
