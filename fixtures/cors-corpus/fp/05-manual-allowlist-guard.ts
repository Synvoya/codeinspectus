declare const req: { headers: { origin: string } };
declare const res: { setHeader(name: string, value: unknown): void };

const allowedOrigins = new Set(["https://app.example.com"]);

export function middleware() {
  if (allowedOrigins.has(req.headers.origin)) {
    res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
}
