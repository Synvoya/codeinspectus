export function h(req: any){
  return client.request(req.params.u + "/x");
}
