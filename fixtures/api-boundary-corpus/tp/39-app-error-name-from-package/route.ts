import { GatewayTimeoutError } from "http-gateway-client";

declare function callGateway(): Promise<unknown>;

export async function GET() {
  try {
    return Response.json(await callGateway());
  } catch (err) {
    if (err instanceof GatewayTimeoutError) return Response.json({ error: err.message }, { status: 504 });
    return Response.json({ error: "Gateway failed" }, { status: 500 });
  }
}
