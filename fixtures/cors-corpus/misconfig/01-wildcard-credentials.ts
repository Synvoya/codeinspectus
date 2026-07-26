import cors from "cors";

export const invalidCors = cors({ origin: "*", credentials: true });
