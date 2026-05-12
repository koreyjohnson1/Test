const http = require("node:http");
const crypto = require("node:crypto");
const validateToken = require("../src/jwt/validateToken");
const { clearJwksCache } = require("../src/jwt/jwksCache");
const {
  UnsupportedAlgorithmError,
  TokenExpiredError,
  TokenNotYetValidError,
  IssuerMismatchError,
  AudienceMismatchError,
  UnknownKeyError,
  InvalidSignatureError,
  MalformedTokenError,
} = require("../src/jwt/errors");

function base64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function createJwt({ header, payload, privateKey }) {
  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const signature = crypto.sign(
    "RSA-SHA256",
    Buffer.from(signingInput),
    privateKey
  );

  return `${signingInput}.${base64url(signature)}`;
}

describe("validateToken", () => {
  let server;
  let jwksUri;
  let privateKey;
  let publicJwk;
  let requestCount;

  const issuer = "https://issuer.example.com/";
  const audience = "api://documents";

  beforeEach((done) => {
    clearJwksCache();
    requestCount = 0;

    const pair = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });

    privateKey = pair.privateKey;
    publicJwk = pair.publicKey.export({ format: "jwk" });
    publicJwk.kid = "test-key";
    publicJwk.alg = "RS256";
    publicJwk.use = "sig";

    server = http.createServer((req, res) => {
      requestCount += 1;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ keys: [publicJwk] }));
    });

    server.listen(0, () => {
      const { port } = server.address();
      jwksUri = `http://127.0.0.1:${port}/.well-known/jwks.json`;
      done();
    });
  });

  afterEach((done) => {
    server.close(done);
  });

  function validPayload(overrides = {}) {
    const now = Math.floor(Date.now() / 1000);

    return {
      sub: "user_123",
      iss: issuer,
      aud: audience,
      exp: now + 300,
      nbf: now - 10,
      scope: "documents:read documents:write",
      ...overrides,
    };
  }

  function validToken(overrides = {}) {
    return createJwt({
      header: {
        alg: "RS256",
        kid: "test-key",
        typ: "JWT",
        ...overrides.header,
      },
      payload: validPayload(overrides.payload),
      privateKey,
    });
  }

  const options = () => ({
    jwksUri,
    issuer,
    audience,
    clockSkewSeconds: 0,
  });

  test("valid RS256 token returns payload", async () => {
    const payload = await validateToken(validToken(), options());

    expect(payload.sub).toBe("user_123");
  });

  test("malformed token is rejected", async () => {
    await expect(validateToken("not-a-jwt", options())).rejects.toBeInstanceOf(
      MalformedTokenError
    );
  });

  test("unsupported algorithm is rejected", async () => {
    const token = validToken({
      header: {
        alg: "HS256",
      },
    });

    await expect(validateToken(token, options())).rejects.toBeInstanceOf(
      UnsupportedAlgorithmError
    );
  });

  test("missing kid is rejected", async () => {
    const token = createJwt({
      header: {
        alg: "RS256",
      },
      payload: validPayload(),
      privateKey,
    });

    await expect(validateToken(token, options())).rejects.toBeInstanceOf(
      UnknownKeyError
    );
  });

  test("expired token is rejected", async () => {
    const now = Math.floor(Date.now() / 1000);

    const token = validToken({
      payload: {
        exp: now - 1,
      },
    });

    await expect(validateToken(token, options())).rejects.toBeInstanceOf(
      TokenExpiredError
    );
  });

  test("future nbf token is rejected", async () => {
    const now = Math.floor(Date.now() / 1000);

    const token = validToken({
      payload: {
        nbf: now + 300,
      },
    });

    await expect(validateToken(token, options())).rejects.toBeInstanceOf(
      TokenNotYetValidError
    );
  });

  test("wrong issuer is rejected", async () => {
    const token = validToken({
      payload: {
        iss: "https://evil.example.com/",
      },
    });

    await expect(validateToken(token, options())).rejects.toBeInstanceOf(
      IssuerMismatchError
    );
  });

  test("wrong audience is rejected", async () => {
    const token = validToken({
      payload: {
        aud: "api://other-service",
      },
    });

    await expect(validateToken(token, options())).rejects.toBeInstanceOf(
      AudienceMismatchError
    );
  });

  test("audience array is accepted", async () => {
    const token = validToken({
      payload: {
        aud: ["api://other-service", audience],
      },
    });

    const payload = await validateToken(token, options());

    expect(payload.sub).toBe("user_123");
  });

  test("invalid signature is rejected", async () => {
    const token = validToken();
    const [encodedHeader, encodedPayload, encodedSignature] = token.split(".");

    const payload = JSON.parse(
      Buffer.from(encodedPayload, "base64url").toString("utf8")
    );

    payload.sub = "attacker";

    const tamperedPayload = Buffer.from(JSON.stringify(payload)).toString(
      "base64url"
    );

    const tampered = `${encodedHeader}.${tamperedPayload}.${encodedSignature}`;

    await expect(validateToken(tampered, options())).rejects.toBeInstanceOf(
      InvalidSignatureError
    );
  });

  test("JWKS is cached for repeated validations", async () => {
    await validateToken(validToken(), options());
    await validateToken(validToken(), options());

    expect(requestCount).toBe(1);
  });
});