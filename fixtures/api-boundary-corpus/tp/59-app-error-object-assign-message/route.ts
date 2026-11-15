class MailboxFullError extends Error {}

async function deliver(body: string): Promise<void> {
  const response = await fetch("https://relay.invalid/deliver", { method: "POST", body });
  if (response.status === 507) {
    throw Object.assign(new MailboxFullError("The mailbox is full"), { message: await response.text() });
  }
}

export async function POST(request: Request) {
  try {
    await deliver(await request.text());
    return Response.json({ ok: true });
  } catch (err) {
    if (err instanceof MailboxFullError) return Response.json({ error: err.message }, { status: 507 });
    return Response.json({ error: "Delivery failed" }, { status: 500 });
  }
}
