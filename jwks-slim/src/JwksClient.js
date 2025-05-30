const debug = require("debug")("jwks-slim");
const { retrieveSigningKey } = require("./utils");
const { request, cacheSigningKey, callbackSupport } = require("./wrappers");
const { JwksError, SigningKeyNotFoundError } = require("./errors");

class JwksClient {
  constructor(options) {
    this.options = {
      cache: true,
      ...options,
    };

    // Initialize wrappers.
    if (this.options.cache) {
      this.getSigningKey = cacheSigningKey(this, options);
    }

    this.getSigningKey = callbackSupport(this, options);
  }

  async getKeys() {
    try {
      const res = await request({
        uri: this.options.jwksUri,
        headers: this.options.requestHeaders,
      });

      return res.keys;
    } catch (err) {
      debug("Failure:", errorMsg || err);
      throw new JwksError(err.message);
    }
  }

  async getSigningKey(kid) {
    try {
      if (kid === undefined || kid === null) {
        debug("No KID specified");
        throw new SigningKeyNotFoundError("No KID specified");
      }

      const keys = await this.getKeys();

      if (!keys || !keys.length) {
        debug("The JWKS endpoint did not contain any keys");
        throw new SigningKeyNotFoundError(
          "The JWKS endpoint did not contain any keys"
        );
      }

      const jwk = keys.find((k) => k.kid === kid);

      if (!jwk) {
        debug(`Unable to find key for kid ${kid}`);
        throw new SigningKeyNotFoundError(`Unable to find key for kid ${kid}`);
      }

      const signingKey = await retrieveSigningKey(jwk);

      if (!signingKey) {
        debug(`Unable to find signing key for kid ${kid}`);
        throw new SigningKeyNotFoundError(
          `Unable to find signing key for kid ${kid}`
        );
      }

      return signingKey;
    } catch (err) {
      throw err;
    }
  }
}

module.exports = {
  JwksClient,
};
