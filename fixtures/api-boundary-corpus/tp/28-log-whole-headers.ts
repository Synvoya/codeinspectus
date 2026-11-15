declare const logger: { debug(...values: unknown[]): void };

export function traceRequest(request: { headers: Record<string, string> }) {
  logger.debug("headers", request.headers);
}
