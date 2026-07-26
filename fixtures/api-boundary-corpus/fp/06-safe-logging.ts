declare const logger: { info(value: unknown): void };
declare const token: string;
declare const userId: string;
declare const request: { headers: unknown; body: unknown };
declare const redact: (value: unknown) => unknown;

export function loginAudit() {
  logger.info({ userId, hasToken: Boolean(token) });
  logger.info({ authorization: "[REDACTED]" });
  logger.info(redact(request.headers));
  logger.info(redact(request.body));
}
