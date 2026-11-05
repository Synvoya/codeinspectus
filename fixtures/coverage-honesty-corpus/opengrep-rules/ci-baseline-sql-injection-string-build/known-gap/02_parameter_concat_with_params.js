// Known gap (precision pass, design 10.6): as 01, with bound parameters after the concatenated text.
// The same query built from request input is reported (tp/10_concat_with_params.js).
module.exports = (db, name, id) => db.query("SELECT * FROM t WHERE name = '" + name + "' AND id = ?", [id]);
