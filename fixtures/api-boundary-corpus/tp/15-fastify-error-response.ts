declare const doWork: () => Promise<void>

export async function handler(reply: any) {
  try {
    await doWork()
  } catch (error: any) {
    return reply.code(500).send({ error: error.stack })
  }
}
