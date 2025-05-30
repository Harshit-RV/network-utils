const memoizer = require("lru-memoizer");
const { promisify, callbackify } = require("util");
require("setimmediate");

function cacheWrapper(client, { cacheMaxEntries = 5, cacheMaxAge = 600000 }) {
  return promisify(
    memoizer({
      hash: (kid) => kid,
      load: callbackify(client.getSigningKey.bind(client)),
      maxAge: cacheMaxAge,
      max: cacheMaxEntries,
    })
  );
}

module.exports.default = cacheWrapper;
