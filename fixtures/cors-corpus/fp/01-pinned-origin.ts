import cors from "cors";

export const safeCors = cors({
  origin: "https://app.example.com",
  credentials: true,
});
