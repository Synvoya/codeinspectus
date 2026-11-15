class QuotaExceededError extends Error {
  code = "QUOTA_EXCEEDED";
}

declare function storeUpload(request: Request): Promise<string>;

export async function POST(request: Request) {
  try {
    return Response.json({ id: await storeUpload(request) });
  } catch (err) {
    if (err instanceof QuotaExceededError) return Response.json({ code: err.code, error: err.message }, { status: 429 });
    return Response.json({ error: "Upload failed" }, { status: 500 });
  }
}
