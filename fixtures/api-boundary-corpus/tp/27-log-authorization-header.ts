export function traceRequest(req: { headers: Record<string, string | undefined> }) {
  console.log("incoming credentials", req.headers["authorization"]);
}
