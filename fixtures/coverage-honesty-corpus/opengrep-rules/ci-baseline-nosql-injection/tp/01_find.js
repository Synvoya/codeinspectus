module.exports = (users, req) => users.find({ name: req.body.name });
