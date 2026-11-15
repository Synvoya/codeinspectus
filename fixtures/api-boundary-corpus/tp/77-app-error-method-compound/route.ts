class ExportQuotaError extends Error {
  constructor() {
    super("The export quota is used up");
  }

  withDetail(detail: string): this {
    this.message += `: ${detail}`;
    return this;
  }
}

async function exportRows(body: string): Promise<void> {
  const response = await fetch("https://exports.invalid/rows", { method: "POST", body });
  if (response.status === 429) throw new ExportQuotaError().withDetail(await response.text());
}

export async function POST(request: Request) {
  try {
    await exportRows(await request.text());
    return Response.json({ ok: true });
  } catch (err) {
    if (err instanceof ExportQuotaError) return Response.json({ error: err.message }, { status: 429 });
    return Response.json({ error: "Export failed" }, { status: 500 });
  }
}
