class InvoiceLockedError extends Error {
  constructor() {
    super("The invoice is locked");
  }

  withDetail(detail: string): this {
    this["message"] = detail;
    return this;
  }
}

async function editInvoice(body: string): Promise<void> {
  const response = await fetch("https://billing.invalid/invoices", { method: "PATCH", body });
  if (response.status === 423) throw new InvoiceLockedError().withDetail(await response.text());
}

export async function PATCH(request: Request) {
  try {
    await editInvoice(await request.text());
    return Response.json({ ok: true });
  } catch (err) {
    if (err instanceof InvoiceLockedError) return Response.json({ error: err.message }, { status: 423 });
    return Response.json({ error: "Could not edit the invoice" }, { status: 500 });
  }
}
