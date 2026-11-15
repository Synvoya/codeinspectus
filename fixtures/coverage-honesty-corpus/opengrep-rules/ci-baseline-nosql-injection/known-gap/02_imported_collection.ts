// KNOWN GAP (documented): a lowercase collection imported from another module has no model proof here.
import { users } from "./db";
export async function login(req: any, res: any) {
  res.json(await users.findOne({ email: req.body.email }));
}
