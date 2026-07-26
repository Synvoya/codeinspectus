declare const schema: {
  validate(value: unknown): { value: { displayName: string }; error?: Error };
};
declare const supabase: {
  from(table: string): { update(value: unknown): Promise<unknown> };
};

export async function PATCH(request: Request) {
  const body = await request.json();
  const { value } = schema.validate(body);
  await supabase.from("profiles").update(value);
  return Response.json({ ok: true });
}
