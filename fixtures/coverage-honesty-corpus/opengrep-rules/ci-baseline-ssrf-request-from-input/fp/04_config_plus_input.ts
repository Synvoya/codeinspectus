export function h(req: any){
  return fetch(config.url + req.query.id);
}
