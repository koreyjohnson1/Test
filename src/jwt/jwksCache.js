const { JwksFetchError } = require("./errors");

const cache = new Map();

async function fetchJwks(jwksUri) {
  try {
    const response = await fetch(jwksUri);

    if (!response.ok) {
      throw new Error(`JWKS fetch failed with ${response.status}`);
    }

    const jwks = await response.json();

    if (!jwks || !Array.isArray(jwks.keys)) {
      throw new Error("Invalid JWKS response");
    }

    return jwks;
  } catch (error) {
    throw new JwksFetchError("Unable to fetch JWKS");
  }
}

async function getJwks(jwksUri, ttlSeconds = 300, forceRefresh = false) {
  const now = Date.now();
  const cached = cache.get(jwksUri);

  if (
    !forceRefresh &&
    cached &&
    now - cached.fetchedAt < ttlSeconds * 1000
  ) {
    return cached.jwks;
  }

  const jwks = await fetchJwks(jwksUri);

  cache.set(jwksUri, {
    jwks,
    fetchedAt: now,
  });

  return jwks;
}

function clearJwksCache() {
  cache.clear();
}

module.exports = {
  getJwks,
  clearJwksCache,
};