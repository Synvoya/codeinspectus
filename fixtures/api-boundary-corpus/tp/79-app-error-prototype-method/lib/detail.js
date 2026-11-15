import { ShareLimitError } from "../errors";

ShareLimitError.prototype.withDetail = function (d) {
  this.message = d;
  return this;
};
