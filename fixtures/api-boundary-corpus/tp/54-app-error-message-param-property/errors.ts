export class GatewayRejectedError extends Error {
  constructor(public readonly message: string, readonly status = 502) {
    super("The gateway rejected the request");
  }
}
