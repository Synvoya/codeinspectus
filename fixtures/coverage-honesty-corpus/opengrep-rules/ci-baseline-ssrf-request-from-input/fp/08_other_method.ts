export function h(req: any){
  return db.query(req.query.u + "x");
}
