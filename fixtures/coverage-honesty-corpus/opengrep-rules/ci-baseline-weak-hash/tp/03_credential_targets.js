const crypto = require("crypto");
function store(user, input) {
  const passwordMd5 = crypto.createHash("md5").update(input).digest("hex");
  user.passwordHash = crypto.createHash("sha1").update(input).digest("hex");
  return passwordMd5;
}
module.exports = { store };
