export function h(req){
  return axios.get(req.body.u + "/y", { timeout: 1 });
}
