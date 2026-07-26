declare const logger: { debug(value: unknown): void };
declare const req: { body: unknown };

export function developmentSearchRoute() {
  logger.debug(req.body);
}
