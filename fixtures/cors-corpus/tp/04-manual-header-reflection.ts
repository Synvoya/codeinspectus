declare const req: { headers: { origin?: string } };
declare const res: { setHeader(name: string, value: unknown): void };

export function middleware() {
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
}
