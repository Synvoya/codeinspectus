class UploadRejectedError extends Error {
  constructor() {
    super("The upload was rejected");
  }
}

async function forward(body: string): Promise<void> {
  const response = await fetch("https://storage.invalid/upload", { method: "POST", body });
  if (!response.ok) {
    const rejected = new UploadRejectedError();
    rejected.message += `: ${await response.text()}`;
    throw rejected;
  }
}

export async function POST(request: Request) {
  try {
    await forward(await request.text());
    return Response.json({ ok: true });
  } catch (err) {
    if (err instanceof UploadRejectedError) return Response.json({ error: err.message }, { status: 422 });
    return Response.json({ error: "Upload failed" }, { status: 500 });
  }
}
