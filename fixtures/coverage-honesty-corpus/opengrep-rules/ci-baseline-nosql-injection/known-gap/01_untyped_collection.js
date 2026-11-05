// Known gap (precision pass, design 10.6): a lowercase receiver in a file that imports neither
// mongoose nor mongodb is not reported; the field hits of this shape were a SQL query builder.
module.exports = (users, req) => users.find({ name: req.body.name });
