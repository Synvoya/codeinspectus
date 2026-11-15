import { ProviderRejectedError } from "./errors";

export async function sendViaProvider(body: string): Promise<void> {
  const response = await fetch("https://provider.invalid/send", { method: "POST", body });
  if (!response.ok) {
    const upstream = (await response.json()) as { message: string };
    throw new ProviderRejectedError(`Provider: ${upstream.message}`);
  }
}
