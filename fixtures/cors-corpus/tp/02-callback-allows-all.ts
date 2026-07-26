import cors from "cors";

export const unsafeCallbackCors = cors({
  credentials: true,
  origin(origin, callback) {
    callback(null, true);
  },
});
