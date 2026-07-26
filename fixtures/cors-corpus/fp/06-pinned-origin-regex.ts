import cors from "cors";

export const safeRegexCors = cors({
  origin: /^https:\/\/app\.example\.com$/,
  credentials: true,
});
