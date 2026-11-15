// Known gap (4.1, M7 Ruling H): a model made with a named `model` import from mongoose is not reported. The 4.1 recall arm for it cost
// main-pass time with no hit on the fresh set, so it moved to 4.2; this file records the shape.
import { Schema, model } from "mongoose";
const account = model("Account", new Schema({ email: String }));
export async function login(req: any, res: any) {
  res.json(await account.findOne({ email: req.body.email }));
}
