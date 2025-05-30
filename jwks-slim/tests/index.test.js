const { JwksClient } = require("../src/JwksClient.js");
require("./mock.js");
describe("JwksClient", () => {
  const jwksUri = "http://jwks-auth-server/.well-known/jwks.json";

  describe("Get Keys", () => {
    it("should return keys", async () => {
      const client = new JwksClient({
        jwksUri,
      });

      const keys = await client.getKeys();
      expect(keys).not.toBeNull();
      expect(keys).toHaveLength(3);
    });
  });

  describe("Get Signing Key", () => {
    it("should give error if kid is not there in the keys", async () => {
      const client = new JwksClient({
        jwksUri,
      });

      try {
        const key = await client.getSigningKey("123");
      } catch (err) {
        expect(err.name).toBe("SigningKeyNotFoundError");
      }
    });

    it("should give error if the key type is not supported", async () => {
      const client = new JwksClient({
        jwksUri,
      });

      try {
        const key = await client.getSigningKey(
          "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ"
        );
      } catch (err) {
        expect(err.name).toBe("JwksError");
        expect(err.message).toBe("Unsupported JWK");
      }
    });

    it("give error if kid is not defined", async () => {
      const client = new JwksClient({
        jwksUri,
      });

      try {
        const key = await client.getSigningKey(undefined);
      } catch (err) {
        expect(err.name).toBe("SigningKeyNotFoundError");
      }
    });

    it("should give the key", async () => {
      const client = new JwksClient({
        jwksUri,
      });

      const key = await client.getSigningKey(
        "RkI5MjI5OUY5ODc1N0Q4QzM0OUYzNkVGMTJDOUEzQkFCOTU3NjE2Rg"
      );

      expect(key).not.toBeNull();
      expect(key.kid).toMatch(
        "RkI5MjI5OUY5ODc1N0Q4QzM0OUYzNkVGMTJDOUEzQkFCOTU3NjE2Rg"
      );
      expect(key.publicKey).toMatch("BEGIN PUBLIC KEY");
    });
  });
});
