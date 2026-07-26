declare const NextResponse: { json(value: unknown, init?: { status: number }): Response };

export async function GET() {
  try {
    throw new Error("provider failure");
  } catch (err) {
    return NextResponse.json({ error: err }, { status: 500 });
  }
}
