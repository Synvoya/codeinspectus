import { StorageFailureError } from "./errors";

async function putObject(key: string): Promise<void> {
  const response = await fetch(`https://storage.invalid/${key}`, { method: "PUT" });
  if (!response.ok) throw new StorageFailureError(response.statusText, response.status >= 500);
}

export async function PUT(request: Request) {
  try {
    await putObject(new URL(request.url).pathname);
    return Response.json({ ok: true });
  } catch (err) {
    if (err instanceof StorageFailureError) {
      return Response.json({ error: err.message }, { status: 502 });
    }
    return Response.json({ error: "Upload failed" }, { status: 500 });
  }
}
