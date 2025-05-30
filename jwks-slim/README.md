# JWKS-Client

A library to retrieve signing keys from a JWKS (JSON Web Key Set) endpoint.

<br>

Environments Supported

- Nodejs
- Web Workers
  - ex. Cloudflare Workers

## Installation

```sh
npm install jwks-slim
```

## Initialization

```js
const { JwksClient } = require("jwks-client");
const client = new JwksClient({
  jwksUri: "your-jwks-endpoint",
  cache: true,  //default: true
  requestHeaders: {}  //optional
});
```

## Usage

```js
const kid = "RkI5MjI5OUY5ODc1N0Q4QzM0OUYzNkVGMTJDOUEzQkFCOTU3NjE2Rg";
const key = await client.getSigningKey(kid);
const signingKey = key.publicKey;
console.log(signingKey);

// Output 
/**
-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAq3DnhgYgLVJknvDA3clA
TozPtjI7yauqD4/ZuqgZn4KzzzkQ4BzJar4jRygpzbghlFn0Luk1mdVKzPUgYj0V
kbRlHyYfcahbgOHixOOnXkKXrtZW7yWGjXPqy/ZJ/+kFBNPAzxy7fDuAzKfU3Rn5
0sBakg95pua14W1oE4rtd4/U+sg2maCq6HgGdCLLxRWwXA8IBtvHZ48i6kxiz9tu
-----END PUBLIC KEY-----
**/

```

## Support

These are the supported key types(kty) :
| key type | support level                        |
| -------- | ------------------------------------ |
| RSA      | all RSA keys                         |
| EC       | _P-256_, _P-384_, and _P-521_ curves |
