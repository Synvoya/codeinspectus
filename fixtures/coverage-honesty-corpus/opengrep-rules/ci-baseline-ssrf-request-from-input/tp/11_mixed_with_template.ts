export function h(req: any, id: string){
  const a = fetch(`/api/${id}`);
  return fetch(req.query.u + "/x");
}
