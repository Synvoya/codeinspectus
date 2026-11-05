export function h(req: any){
  return fetch(String(req.query.u));
}
