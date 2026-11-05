export function h(req: any){
  return fetch("/api/" + req.query.id);
}
