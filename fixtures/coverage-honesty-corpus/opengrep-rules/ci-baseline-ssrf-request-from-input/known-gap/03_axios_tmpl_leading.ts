export function h(req: any){
  return axios.get(`${req.body.u}/y`);
}
