declare const res: { status(code: number): typeof res; json(value: unknown): void };

export function handler() {
  return res.status(500).json({
    error: "SELECT * FROM private_accounts failed at /srv/app/database/query.ts",
  });
}
