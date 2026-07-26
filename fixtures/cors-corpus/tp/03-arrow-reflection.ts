import cors from "cors";

export const unsafeArrowCors = cors({
  origin: (origin, callback) => callback(null, origin),
  credentials: true,
});
