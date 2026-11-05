import { readBody } from "h3";
export async function handler(e: any) {
  const body = await readBody(e);
  return db.execute("UPDATE t SET name = '" + body.name + "'");
}
