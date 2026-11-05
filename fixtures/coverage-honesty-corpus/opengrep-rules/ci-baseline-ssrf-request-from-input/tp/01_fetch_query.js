export function h(req){
  return fetch(req.query.u + "/x");
}
