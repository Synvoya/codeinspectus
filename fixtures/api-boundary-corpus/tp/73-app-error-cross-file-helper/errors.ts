export class SeatReservationError extends Error {
  constructor() {
    super("No seat could be reserved");
  }
}
