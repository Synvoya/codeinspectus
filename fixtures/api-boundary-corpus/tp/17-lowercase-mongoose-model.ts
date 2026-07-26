export async function handler(req: any, userModel: any) {
  return userModel.updateOne({ _id: req.params.id }, req.body)
}
