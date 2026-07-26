declare const res: { status(code: number): typeof res; send(value: unknown): void };

export function handler(error: Error) {
  return res.status(500).send({ stack: error.stack });
}
