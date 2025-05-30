const { JwksClient } = require("../src/JwksClient.js");
require("./mock.js");

describe("JwksClient Cache", () => {
  const jwksUri = "http://jwks-auth-server/.well-known/jwks.json";

  describe("Get Signing Key", () => {
    describe("should cache the key per kid", () => {
      let client;
      beforeAll(async () => {
        client = new JwksClient({
          jwksUri,
          cache: true,
        });

        const key = await client.getSigningKey(
          "RkI5MjI5OUY5ODc1N0Q4QzM0OUYzNkVGMTJDOUEzQkFCOTU3NjE2Rg"
        );

        expect(key).not.toBeNull();
        expect(key.kid).toMatch(
          "RkI5MjI5OUY5ODc1N0Q4QzM0OUYzNkVGMTJDOUEzQkFCOTU3NjE2Rg"
        );
      });

      it("should fetch the cached key for the same kid", async () => {
        const key = await client.getSigningKey(
          "RkI5MjI5OUY5ODc1N0Q4QzM0OUYzNkVGMTJDOUEzQkFCOTU3NjE2Rg"
        );
        expect(key).not.toBeNull();
        expect(global.fetch).toBeCalledTimes(1);
      });

      it("should ignore the cache when the KID isnt cached and make a request", async () => {
        try {
          const key = await client.getSigningKey("abcde");
        } catch (err) {
          expect(global.fetch).toBeCalledTimes(2);
          expect(err.name).toBe("SigningKeyNotFoundError");
        }
      });
    });
  });
});
