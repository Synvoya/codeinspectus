export function h(req: any){
  return axios.get(req.query.u + "/x");
}
