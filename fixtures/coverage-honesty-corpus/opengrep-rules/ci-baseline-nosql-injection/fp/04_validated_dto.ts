import { z } from "zod";
import { User } from "./models";
const Filter = z.object({ email: z.string() });
export async function find(req: any, res: any) {
  const filter = Filter.parse(req.body);
  res.json(await User.find(filter));
}
