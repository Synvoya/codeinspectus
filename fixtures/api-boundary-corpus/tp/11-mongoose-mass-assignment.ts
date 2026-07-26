declare const User: { findByIdAndUpdate(id: string, value: unknown): Promise<unknown> };
declare const req: { params: { id: string }; body: unknown };

export async function updateUser() {
  await User.findByIdAndUpdate(req.params.id, req.body);
}
