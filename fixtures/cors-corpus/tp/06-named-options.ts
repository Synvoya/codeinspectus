import cors from "cors";

const corsOptions = {
  credentials: true,
  origin: true,
  methods: ["GET", "POST"],
};

export const unsafeNamedOptions = cors(corsOptions);
