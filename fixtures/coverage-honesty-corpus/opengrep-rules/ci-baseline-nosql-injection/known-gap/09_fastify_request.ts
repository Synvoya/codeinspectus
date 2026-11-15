// Known gap (4.1, M7 Ruling H): a Fastify `request` source in an inline route handler is not reported. The 4.1 recall arm for it cost
// main-pass time with no hit on the fresh set, so it moved to 4.2; this file records the shape.
import Fastify from "fastify";
import { Member } from "./models";
const app = Fastify();
app.post("/login", async (request: any, reply: any) => {
  return Member.findOne({ handle: request.body.handle });
});
