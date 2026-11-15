export function traceToken(request: Request) {
  console.info("forwarding", request.headers.get("x-auth-token"));
}
