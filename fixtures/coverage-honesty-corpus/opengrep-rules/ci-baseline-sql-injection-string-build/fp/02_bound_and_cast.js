module.exports = (app, db) => {
  app.get("/a", (req) => db.query("SELECT * FROM users WHERE id = $1", [req.params.id]));
  app.get("/b", (req) => db.query("SELECT * FROM users LIMIT " + parseInt(req.query.limit, 10)));
};
