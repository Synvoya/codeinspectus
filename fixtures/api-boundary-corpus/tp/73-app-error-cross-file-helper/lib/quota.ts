import { SeatReservationError } from "../errors";
import { withContext } from "./context";

export async function reserve(body: string): Promise<void> {
  const response = await fetch("https://quota.invalid/reserve", { method: "POST", body });
  if (response.status === 429) throw withContext(new SeatReservationError(), await response.text());
}
