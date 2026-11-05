const vm = require("vm");
exports.calc = (req, res) => {
  const value = vm.runInNewContext("a + b", { a: Number(req.query.a), b: 2 });
  setTimeout(() => res.json({ value }), Number(req.query.delay));
};
