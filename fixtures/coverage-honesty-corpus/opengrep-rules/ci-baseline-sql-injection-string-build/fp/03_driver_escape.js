// Driver escapes from the mysql/mysql2 and pg clients sanitize the value for this query.
const mysql = require("mysql2");
const pool = mysql.createPool({ host: "db" });
module.exports = (app, client) => {
  app.get("/a", (req) => pool.query("SELECT * FROM t WHERE id = " + pool.escape(req.query.id)));
  app.get("/b", (req) => pool.query("SELECT * FROM t WHERE name = " + mysql.escape(req.query.name)));
  app.get("/c", (req) => client.query("SELECT * FROM t WHERE tag = " + client.escapeLiteral(req.query.tag)));
};
