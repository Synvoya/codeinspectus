class QuotaExceededError extends Error {
  code = "QUOTA_EXCEEDED";
}

declare function storeUpload(request: Request): Promise<string>;

export async function POST(request: Request) {
  try {
    return Response.json({ id: await storeUpload(request) });
  } catch (err) {
    if (err instanceof QuotaExceededError) console.warn("quota reached");
    return Response.json({ code: (err as QuotaExceededError).code, error: err.message }, { status: 500 });
  }
}
