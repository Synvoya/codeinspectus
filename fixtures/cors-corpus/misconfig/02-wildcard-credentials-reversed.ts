import cors from "cors";

export const invalidCors = cors({ credentials: true, origin: "*" });
