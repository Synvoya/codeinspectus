export function withContext<T extends { message: string }>(e: T, ctx: string): T {
  e.message = `${ctx}: ${e.message}`;
  return e;
}
