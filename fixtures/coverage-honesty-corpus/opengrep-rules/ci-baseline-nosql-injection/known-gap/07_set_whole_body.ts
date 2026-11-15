// Known gap (4.1, M7 Ruling H): the whole request body used as a `$set` update is not reported. The 4.1 recall arm for it cost
// main-pass time with no hit on the fresh set, so it moved to 4.2; this file records the shape.
import { Profile } from "./models";
export async function update(req: any, res: any) {
  await Profile.updateOne({ _id: req.user.id }, { $set: req.body });
  res.sendStatus(204);
}
