// A SQL query builder's find(), as in the field: no MongoDB model, collection or import.
const query = require("../queries");
module.exports = (req) => query.link.find({ id: req.query.id });
