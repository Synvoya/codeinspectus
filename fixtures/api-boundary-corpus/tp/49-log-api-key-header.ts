export function traceKey(req: { headers: Record<string, string | undefined> }) {
  console.log("partner call", req.headers["x-api-key"]);
}
