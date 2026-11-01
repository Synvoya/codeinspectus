export function h(req: any){
  return fetch(url, { headers: req.headers });
}
