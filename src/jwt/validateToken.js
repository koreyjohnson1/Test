const crypto = require("node:crypto");
const { getJwks } = require("./jwksCache");
const {
  MalformedTokenError,
  UnsupportedAlgorithmError,
  UnknownKeyError,
  InvalidSignatureError,
  TokenExpiredError,
  TokenNotYetValidError,
  IssuerMismatchError,
  AudienceMismatchError,
} = require("./errors");

// Use a positive allowlist instead of rejecting only "none".
// A denylist is unsafe because attackers can switch to another unexpected
// algorithm, such as HS256, and attempt algorithm-confusion attacks.
const ALLOWED_ALGORITHMS = new Set(["RS256"]);

function base64urlToBuffer(value) {
  if (typeof value !== "string" || value.length === 0) {
    throw new MalformedTokenError("Invalid base64url value");
  }

  const padded = value.padEnd(
    value.length + ((4 - (value.length % 4)) % 4),
    "="
  );

  return Buffer.from(
    padded.replace(/-/g, "+").replace(/_/g, "/"),
    "base64"
  );
}

function decodeJsonSegment(segment) {
  try {
    return JSON.parse(base64urlToBuffer(segment).toString("utf8"));
  } catch {
    throw new MalformedTokenError("JWT segment is not valid JSON");
  }
}

function validateAudience(tokenAudience, expectedAudience) {
  if (Array.isArray(tokenAudience)) {
    return tokenAudience.includes(expectedAudience);
  }

  return tokenAudience === expectedAudience;
}

function findSigningKey(jwks, kid) {
  return jwks.keys.find(
    (key) =>
      key.kid === kid &&
      key.kty === "RSA" &&
      (!key.use || key.use === "sig") &&
      (!key.alg || key.alg === "RS256")
  );
}

async function validateToken(token, options) {
  const {
    jwksUri,
    issuer,
    audience,
    clockSkewSeconds = 30,
    jwksCacheTtlSeconds = 300,
    jwksForcedRefreshCooldownSeconds = 30,
  } = options || {};

  if (!jwksUri || !issuer || !audience) {
    throw new Error("jwksUri, issuer, and audience are required");
  }

  if (typeof token !== "string") {
    throw new MalformedTokenError("Token must be a string");
  }

  const parts = token.split(".");

  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new MalformedTokenError(
      "JWT must contain header, payload, and signature"
    );
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const header = decodeJsonSegment(encodedHeader);
  const payload = decodeJsonSegment(encodedPayload);

  if (!ALLOWED_ALGORITHMS.has(header.alg)) {
    throw new UnsupportedAlgorithmError("Unsupported JWT algorithm");
  }

  if (!header.kid) {
    throw new UnknownKeyError("JWT header is missing kid");
  }

  let jwks = await getJwks(jwksUri, jwksCacheTtlSeconds);
  let jwk = findSigningKey(jwks, header.kid);

  if (!jwk) {
    jwks = await getJwks(
      jwksUri,
      jwksCacheTtlSeconds,
      true,
      jwksForcedRefreshCooldownSeconds
    );

    jwk = findSigningKey(jwks, header.kid);
  }

  if (!jwk) {
    throw new UnknownKeyError("No matching JWK found");
  }

  let publicKey;

  try {
    publicKey = crypto.createPublicKey({
      key: jwk,
      format: "jwk",
    });
  } catch {
    throw new UnknownKeyError("Invalid JWK");
  }

  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = base64urlToBuffer(encodedSignature);

  const isValidSignature = crypto.verify(
    "RSA-SHA256",
    Buffer.from(signingInput),
    publicKey,
    signature
  );

  if (!isValidSignature) {
    throw new InvalidSignatureError("Invalid JWT signature");
  }

  const now = Math.floor(Date.now() / 1000);
  const skew = Number(clockSkewSeconds);

  if (typeof payload.exp !== "number" || payload.exp <= now - skew) {
    throw new TokenExpiredError("Token is expired");
  }

  if (typeof payload.nbf === "number" && payload.nbf > now + skew) {
    throw new TokenNotYetValidError("Token is not yet valid");
  }

  if (payload.iss !== issuer) {
    throw new IssuerMismatchError("Issuer mismatch");
  }

  if (!validateAudience(payload.aud, audience)) {
    throw new AudienceMismatchError("Audience mismatch");
  }

  return payload;
}

module.exports = validateToken;