export function h(req: any){
  return fetch(`https://${req.query.host}/x`);
}
