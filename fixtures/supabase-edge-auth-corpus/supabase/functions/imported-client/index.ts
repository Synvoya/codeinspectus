import { db } from "./client.ts";

Deno.serve(async () => Response.json(await db.from("accounts").select()));
