const { JWS, JWK } = require('node-jose');

const JWKS_TEST = {
  "keys": [
    {
      "key_ops": [
        "verify",
        "sign"
      ],
      "kid": "2aedafba-8170-4064-b704-ce92b7c89cc6",
      "kty": "EC",
      "crv": "P-256",
      "x": "6r8PYwqfZbq_QzoMA4tzJJsYUIIXdeyPA27qTgEJCDw=",
      "y": "Cf2clfAfFuuCB06NMfIat9ultkMyrMQO9Hd2H7O9ZVE=",
      "d": "N1vu0UQUp0vLfaNeM0EDbl4quvvL6m_ltjoAXXzkI3U=",
    }
  ]
};

async function getToken(scopes) {
    const keystore = await JWK.asKeyStore(JWKS_TEST);
    const [key] = keystore.all({ use: "sig" });
    const now = new Date().getTime() / 1000;

    const payload = {
      scopes: scopes,
      sub: "test@example.com",
      exp: now + 1800,
      iat: now,
    };

    return (
      JWS.createSign({compact: true, jwk: key}, key)
         .update(JSON.stringify(payload))
         .final()
    );
}

module.exports = getToken;
