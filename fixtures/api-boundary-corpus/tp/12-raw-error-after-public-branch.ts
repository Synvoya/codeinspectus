class ConflictError extends Error {}

export function handler(error: unknown) {
  if (error instanceof ConflictError) {
    console.warn("Known conflict");
  }

  return Response.json({ error }, { status: 500 });
}
