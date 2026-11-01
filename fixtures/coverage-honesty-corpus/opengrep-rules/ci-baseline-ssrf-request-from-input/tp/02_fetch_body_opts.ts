export async function h(req: any){
  return fetch(req.body.url + path, { method: "GET" });
}
