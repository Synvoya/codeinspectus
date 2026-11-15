declare const logger: { info(...values: unknown[]): void; debug(...values: unknown[]): void };
declare const user: { tokenExpiry: Date };
declare const session: { token: { expiresAt: Date } };
declare const token: string;
declare const secret: string | undefined;

export function chargeAudit(req: { headers: Record<string, string>; body: { amount: number } }) {
  console.log(user.tokenExpiry);
  logger.info("token length", token.length);
  logger.debug("secret type", typeof secret);
  console.log("content type", req.headers["content-type"]);
  console.warn(`client amount ${req.body.amount}`);
  console.info(`session token expires ${session.token.expiresAt}`);
}
