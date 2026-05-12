const ROLES_CLAIM = "https://example.com/roles";

function requireRole(role) {
  return function roleMiddleware(req, res, next) {
    const roles = req.auth && req.auth[ROLES_CLAIM];

    if (!Array.isArray(roles) || !roles.includes(role)) {
      return res.status(403).json({
        error: "forbidden",
        requiredRole: role,
      });
    }

    return next();
  };
}

module.exports = requireRole;