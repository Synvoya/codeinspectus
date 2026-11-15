export class QuotaError extends Error {}

export class ProviderQuotaError extends QuotaError {}

export function localQuota(): never {
  throw new QuotaError("You have used your monthly quota");
}
