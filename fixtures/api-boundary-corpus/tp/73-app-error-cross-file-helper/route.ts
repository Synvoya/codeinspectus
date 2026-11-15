import { SeatReservationError } from "./errors";
import { reserve } from "./lib/quota";

export async function POST(request: Request) {
  try {
    await reserve(await request.text());
    return Response.json({ ok: true });
  } catch (err) {
    if (err instanceof SeatReservationError) return Response.json({ error: err.message }, { status: 429 });
    return Response.json({ error: "Could not reserve quota" }, { status: 500 });
  }
}
