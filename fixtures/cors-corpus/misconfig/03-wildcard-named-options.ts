import cors from "cors";

const corsOptions = {
  origin: "*",
  credentials: true,
};

export const invalidNamedOptions = cors(corsOptions);
