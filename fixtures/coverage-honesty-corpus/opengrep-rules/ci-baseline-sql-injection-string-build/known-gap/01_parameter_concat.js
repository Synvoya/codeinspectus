// Known gap (precision pass, design 10.6): a query built from a function parameter is not reported
// unless HTTP request input reaches it in the same file. Field hits of this shape were constants.
module.exports = (db, id) => db.query("SELECT * FROM users WHERE id = " + id);
