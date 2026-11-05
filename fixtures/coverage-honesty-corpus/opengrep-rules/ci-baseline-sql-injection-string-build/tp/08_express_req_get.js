module.exports = (app, db) => {
  app.get("/u", (req) => db.query("SELECT * FROM t WHERE ua = '" + req.get("user-agent") + "'"));
  app.get("/v", (req) => db.query(`SELECT * FROM t WHERE lang = '${req.header("accept-language")}'`));
};
