declare const logger: { error(value: unknown): void };
declare const toPublicError: (error: unknown) => { error: string };

export function generic(error: unknown) {
  logger.error({ error });
  return Response.json({ error: "Internal server error" }, { status: 500 });
}

export function mapped(error: unknown) {
  return Response.json(toPublicError(error), { status: 500 });
}

class ConflictError extends Error {
  code = "CONFLICT";
}

export function knownPublicError(error: unknown) {
  if (error instanceof ConflictError) {
    return Response.json({ error: { code: error.code, message: error.message } }, { status: 409 });
  }
  return Response.json({ error: "Internal server error" }, { status: 500 });
}
