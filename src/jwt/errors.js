class JwtValidationError extends Error {
  constructor(message = "JWT validation failed") {
    super(message);
    this.name = this.constructor.name;
  }
}

class MalformedTokenError extends JwtValidationError {}
class UnsupportedAlgorithmError extends JwtValidationError {}
class UnknownKeyError extends JwtValidationError {}
class InvalidSignatureError extends JwtValidationError {}
class TokenExpiredError extends JwtValidationError {}
class TokenNotYetValidError extends JwtValidationError {}
class IssuerMismatchError extends JwtValidationError {}
class AudienceMismatchError extends JwtValidationError {}
class JwksFetchError extends JwtValidationError {}

module.exports = {
  JwtValidationError,
  MalformedTokenError,
  UnsupportedAlgorithmError,
  UnknownKeyError,
  InvalidSignatureError,
  TokenExpiredError,
  TokenNotYetValidError,
  IssuerMismatchError,
  AudienceMismatchError,
  JwksFetchError,
};