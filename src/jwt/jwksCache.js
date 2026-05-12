const { JwksFetchError } = require("./errors");

const cache = new Map();

const DEFAULT_FORCE_REFRESH_COOLDOWN_SECONDS = 30;

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
  } catch {
    throw new JwksFetchError("Unable to fetch JWKS");
  }
}

async function getJwks(
  jwksUri,
  ttlSeconds = 300,
  forceRefresh = false,
  forceRefreshCooldownSeconds = DEFAULT_FORCE_REFRESH_COOLDOWN_SECONDS
) {
  const now = Date.now();
  const cached = cache.get(jwksUri);

  const cacheIsFresh =
    cached && now - cached.fetchedAt < ttlSeconds * 1000;

  if (!forceRefresh && cacheIsFresh) {
    return cached.jwks;
  }

  if (forceRefresh && cached) {
    const lastForcedRefreshAt = cached.lastForcedRefreshAt || 0;
    const cooldownMs = forceRefreshCooldownSeconds * 1000;
    const refreshIsCoolingDown = now - lastForcedRefreshAt < cooldownMs;

    if (refreshIsCoolingDown) {
      return cached.jwks;
    }
  }

  const jwks = await fetchJwks(jwksUri);

  cache.set(jwksUri, {
    jwks,
    fetchedAt: now,
    lastForcedRefreshAt: forceRefresh
      ? now
      : cached && cached.lastForcedRefreshAt
      ? cached.lastForcedRefreshAt
      : 0,
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