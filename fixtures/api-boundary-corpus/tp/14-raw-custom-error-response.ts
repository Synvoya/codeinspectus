class ProviderConflictError extends Error {
  code = "PROVIDER_CONFLICT";
}

export function handler(error: unknown) {
  if (error instanceof ProviderConflictError) {
    return Response.json({ error }, { status: 409 });
  }
  return Response.json({ error: "Internal server error" }, { status: 500 });
}
