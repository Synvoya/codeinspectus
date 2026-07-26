class UserError extends Error {
  constructor(message: string, public data: Record<string, unknown> = {}) {
    super(message)
  }
}

export function handler(error: unknown) {
  if (error instanceof UserError) {
    return new Response(JSON.stringify({ error: error.message, data: error.data }), {
      status: 400,
    })
  }
  return new Response(JSON.stringify({ error: "Internal server error" }), { status: 500 })
}
