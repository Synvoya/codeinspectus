import cors from "cors";

const allowed = new Set(["https://app.example.com"]);
export const safeCallbackCors = cors({
  credentials: true,
  origin(origin, callback) {
    callback(null, Boolean(origin && allowed.has(origin)));
  },
});
