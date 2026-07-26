declare const User: { findByIdAndUpdate(id: string, value: unknown): Promise<unknown> };
declare const req: { params: { id: string }; body: { displayName: string } };

export async function updateUser() {
  await User.findByIdAndUpdate(req.params.id, { displayName: req.body.displayName });
}
