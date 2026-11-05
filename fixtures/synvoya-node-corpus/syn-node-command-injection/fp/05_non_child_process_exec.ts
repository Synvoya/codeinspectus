import { exec } from "./graphql-runner";
export async function run(req: any) {
  const query = "query { user(id: " + req.body.id + ") { name } }";
  return exec(query);
}
