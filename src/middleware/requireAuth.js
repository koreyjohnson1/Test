const validateToken = require("../jwt/validateToken");

function requireAuth(options) {
  return async function authMiddleware(req, res, next) {
    const header = req.get("authorization");

    if (!header) {
      return res.status(401).json({ error: "missing_token" });
    }

    const match = header.match(/^Bearer\s+(.+)$/i);

    if (!match) {
      return res.status(401).json({ error: "missing_token" });
    }

    try {
      const payload = await validateToken(match[1], options);
      req.auth = payload;
      return next();
    } catch (error) {
      return res.status(401).json({
        error: "invalid_token",
        reason: error.name || "JwtValidationError",
      });
    }
  };
}

module.exports = requireAuth;