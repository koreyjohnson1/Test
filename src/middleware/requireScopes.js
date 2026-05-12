function parseScopes(scopeClaim) {
  if (typeof scopeClaim !== "string") {
    return new Set();
  }

  return new Set(
    scopeClaim
      .split(" ")
      .map((scope) => scope.trim())
      .filter(Boolean)
  );
}

function requireScopes(...requiredScopes) {
  return function scopeMiddleware(req, res, next) {
    const grantedScopes = parseScopes(req.auth && req.auth.scope);

    const hasAllScopes = requiredScopes.every((scope) =>
      grantedScopes.has(scope)
    );

    if (!hasAllScopes) {
      return res.status(403).json({
        error: "insufficient_scope",
        required: requiredScopes,
      });
    }

    return next();
  };
}

module.exports = requireScopes;