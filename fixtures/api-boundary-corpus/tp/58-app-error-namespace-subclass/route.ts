import { SeatLimitError } from "./errors";
import { reserveSeat } from "./billing";

export async function POST() {
  try {
    await reserveSeat();
    return Response.json({ ok: true });
  } catch (err) {
    if (err instanceof SeatLimitError) return Response.json({ error: err.message }, { status: 402 });
    return Response.json({ error: "Could not reserve a seat" }, { status: 500 });
  }
}
