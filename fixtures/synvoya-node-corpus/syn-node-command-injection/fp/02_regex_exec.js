const pattern = /id=(\d+)/;
exports.parse = (req) => {
  const match = pattern.exec(req.query.s);
  return match && match[1];
};
