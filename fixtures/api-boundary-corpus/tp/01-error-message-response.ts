export async function POST(request: Request) {
  try {
    await request.json();
    throw new Error("database unavailable");
  } catch (error) {
    return Response.json(
      { error: error instanceof Error ? error.message : String(error) },
      { status: 500 },
    );
  }
}
