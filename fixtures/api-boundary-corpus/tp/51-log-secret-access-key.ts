declare const logger: { debug(...values: unknown[]): void };

export function configureStorage(credentials: { accessKeyId: string; secretAccessKey: string }) {
  logger.debug("storage credentials", credentials.secretAccessKey);
}
