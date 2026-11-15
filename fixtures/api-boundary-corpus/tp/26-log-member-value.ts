declare const logger: { info(value: unknown): void };

export function signupAudit(user: { id: string; password: string }) {
  logger.info({ user: user.id, password: user.password });
}
