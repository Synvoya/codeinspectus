declare const logger: { debug(value: unknown): void };
declare const req: { body: unknown };

export function loginRoute() {
  logger.debug(req.body);
}
