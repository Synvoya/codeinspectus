import * as errors from "./errors";

export class BillingSeatLimitError extends errors.SeatLimitError {}

export async function reserveSeat(): Promise<void> {
  const response = await fetch("https://billing.invalid/seats", { method: "POST" });
  if (response.status === 402) throw new BillingSeatLimitError(await response.text());
}
