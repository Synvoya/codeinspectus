export class SeatLimitError extends Error {}

export function seatLimit(): never {
  throw new SeatLimitError("Your plan has no free seats");
}
