const { JwksClient } = require("./JwksClient");
const errors = require("./errors");

module.exports = (options) => {
  return new JwksClient(options);
};
module.exports.JwksClient = JwksClient;

module.exports.JwksError = errors.JwksError;
module.exports.SigningKeyNotFoundError = errors.SigningKeyNotFoundError;
