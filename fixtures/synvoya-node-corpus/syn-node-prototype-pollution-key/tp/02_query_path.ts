const store: Record<string, any> = {};
export function setPref(req: any) {
  store[req.query.group][req.query.name] = req.query.value;
}
