module.exports = (app, db) => {
  app.get("/users", (req, res) => db.query("SELECT * FROM users WHERE id = " + req.query.id).then((r) => res.json(r)));
};
