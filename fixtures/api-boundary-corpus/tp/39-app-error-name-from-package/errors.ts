export class GatewayTimeoutError extends Error {}

export function timeout(): never {
  throw new GatewayTimeoutError("The gateway timed out");
}
