const vm = require("node:vm");
exports.calc = (req, res) => {
  const expression = req.body.expr;
  const value = vm.runInNewContext(expression, { Math });
  res.json({ value });
};
