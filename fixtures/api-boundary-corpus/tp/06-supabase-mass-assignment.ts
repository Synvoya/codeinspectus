declare const supabase: {
  from(table: string): { insert(value: unknown): Promise<unknown> };
};

export async function POST(request: Request) {
  await supabase.from("profiles").insert(await request.json());
  return Response.json({ ok: true });
}
