export function h(req: any){
  return fetch(`${req.query.u}`);
}
