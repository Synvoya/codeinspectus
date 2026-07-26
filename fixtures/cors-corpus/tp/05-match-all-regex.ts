import cors from "cors";

export const unsafeRegexCors = cors({ origin: /.*/, credentials: true });
