import type { NextApiRequest, NextApiResponse } from "next";

declare function syncMailbox(): Promise<void>;

export default async function handler(_req: NextApiRequest, res: NextApiResponse) {
  try {
    await syncMailbox();
    res.json({ ok: true });
  } catch (err: any) {
    res.json({ error: err.message });
  }
}
