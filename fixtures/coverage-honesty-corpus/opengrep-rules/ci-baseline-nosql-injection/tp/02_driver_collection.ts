export const byName = (db: any, req: any) => db.collection("users").find({ name: req.query.name });
