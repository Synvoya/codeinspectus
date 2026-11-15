// KNOWN GAP (documented, both implementations): the hash object is updated with the password in a later
// statement; neither the native rule nor the Opengrep rule follows the object, so nothing is reported.
const crypto = require("crypto");
module.exports = (password) => {
  const h = crypto.createHash("md5");
  h.update(password);
  return h.digest("hex");
};
