const db = require("./db");
const { exec: runStatement } = require("./runner");
exports.find = (req) => {
  const statement = "find " + req.query.name;
  db.exec(statement);
  return runStatement(statement);
};
