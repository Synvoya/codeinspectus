declare const logger: { info(value: unknown): void };
declare const password: string;
declare const token: string;
declare const secret: string;
declare const req: { cookies: unknown };

export function login(request: Request) {
  logger.info({
    authorization: request.headers.get("authorization"),
    cookies: req.cookies,
    password,
    token,
    secret,
  });
}
