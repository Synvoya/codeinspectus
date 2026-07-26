declare const res: { setHeader(name: string, value: unknown): void };

export function middleware() {
  res.setHeader("Access-Control-Allow-Origin", "https://app.example.com");
  res.setHeader("Access-Control-Allow-Credentials", "true");
}
