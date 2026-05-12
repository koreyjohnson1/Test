# Code Review Findings

## 1. JWKS cache never expires

**Category:** Key management  
**Severity:** High  

**Issue:** The implementation caches JWKS forever once `cachedJwks` is populated. If a signing key is rotated, removed, or compromised, the API may continue trusting stale keys indefinitely.

**Exploit scenario:** An attacker obtains a private key that is later rotated out of the authorization server. This API may continue accepting tokens signed by the old key because it never refreshes the JWKS cache.

**Fix:** Cache JWKS with a bounded TTL, such as five minutes. Refresh on TTL expiry. Also perform a controlled forced refresh when a token references an unknown `kid`.

## 2. No protection against unknown `kid` refetch abuse

**Category:** Denial of service  
**Severity:** High  

**Issue:** A validator that refetches JWKS on every unknown `kid` can be abused by attackers sending forged tokens with random key IDs.

**Exploit scenario:** The attacker sends many JWTs with random `kid` headers. Each request causes an outbound JWKS request, consuming API resources and potentially overwhelming the authorization server.

**Fix:** Use a JWKS cache, force-refresh at most once per unknown `kid`, debounce refreshes per JWKS URI, limit fetch concurrency, and briefly negative-cache unknown key IDs.

## 3. Authorization header parser does not require Bearer format

**Category:** Authentication bypass / parser ambiguity  
**Severity:** Medium  

**Issue:** The implementation uses `auth.split(' ')[1]` without verifying the header is exactly `Authorization: Bearer <token>`.

**Exploit scenario:** Malformed headers may be parsed inconsistently by proxies, middleware, or application code. This can cause confusing authentication behavior and makes it harder to reason about the security boundary.

**Fix:** Require an exact Bearer-token pattern such as `/^Bearer\s+(.+)$/i`. Reject missing or malformed headers with a stable 401 response.

## 4. Uses `jwt.decode()` before verification

**Category:** Trusting attacker-controlled input  
**Severity:** High  

**Issue:** `jwt.decode()` parses the token without verifying the signature. The code then uses values from the decoded header to choose a key and algorithm.

**Exploit scenario:** An attacker can provide any `kid` or `alg` value in the unverified header. Even if final verification later fails, the server has already made security decisions based on attacker-controlled data.

**Fix:** Treat decoded header data as untrusted. Use it only for limited key lookup after strict structural validation. Never use it to choose allowed algorithms dynamically.

## 5. Reflects attacker-controlled `kid` in the response

**Category:** Information disclosure / unsafe error handling  
**Severity:** Low to Medium  

**Issue:** The error response includes `kid: decoded?.header?.kid`. This reflects attacker-controlled input back to the client.

**Exploit scenario:** Attackers can use this behavior to test parser behavior, inject misleading values into logs or client-side diagnostics, and enumerate how the API handles key IDs.

**Fix:** Return a stable error such as `{ "error": "invalid_token", "reason": "UnknownKeyError" }`. Log detailed values server-side only with safe structured logging.

## 6. Leaks the entire JWKS cache in an error response

**Category:** Information disclosure  
**Severity:** Medium  

**Issue:** The response includes `cachedKeys: cachedJwks`.

**Exploit scenario:** Although JWKS contains public keys, exposing internal cache state gives attackers implementation details, key IDs, algorithms, issuer configuration hints, and operational behavior.

**Fix:** Never return key material, cache contents, or internal auth configuration to clients. Return a generic invalid-token response.

## 7. Accepts algorithm from JWT header

**Category:** Algorithm confusion  
**Severity:** Critical  

**Issue:** The code passes `algorithms: [decoded?.header?.alg]` into verification. The allowed algorithm is chosen by the attacker-controlled token header.

**Exploit scenario:** An attacker may try to switch algorithms, such as from `RS256` to `HS256`, and exploit algorithm confusion if the verifier treats public key material as an HMAC secret or otherwise accepts unexpected algorithms.

**Fix:** Use a positive allowlist controlled by the server, such as `algorithms: ["RS256"]`. Reject `none`, `HS256`, or any unsupported algorithm before verification.

## 8. No audience validation

**Category:** Token replay / confused deputy  
**Severity:** Critical  

**Issue:** The code checks issuer but does not check the `aud` claim.

**Exploit scenario:** A token issued for another API or service may be replayed against this API. The user may have authorized a different resource server, but this API would still accept the token.

**Fix:** Require exact audience validation. For example, verify `aud === "https://api.example.com"` or allow array-form audience only when it contains the expected value.

## 9. Uses `key.n` directly as the verification key

**Category:** Cryptographic implementation error  
**Severity:** High  

**Issue:** In a JWK, `n` is only the RSA modulus. It is not a complete public key. A verifier needs the full key material, including exponent `e`, and should construct a proper public key object.

**Exploit scenario:** Incorrect key construction may reject valid tokens, verify incorrectly, or create fragile behavior depending on library assumptions.

**Fix:** Convert the full JWK to a public key object using a trusted crypto API, such as `crypto.createPublicKey({ key: jwk, format: "jwk" })`, then verify the RS256 signature.

## 10. Returns raw verification errors to clients

**Category:** Information disclosure  
**Severity:** Medium  

**Issue:** The catch block returns `{ error: err.message }`.

**Exploit scenario:** Attackers can learn which validation step failed, which algorithms are accepted, whether a key ID exists, whether the token was expired, and other implementation details useful for probing.

**Fix:** Map internal errors to stable external error codes. For example, return `{ "error": "invalid_token", "reason": "TokenExpiredError" }` only if the API intentionally exposes typed reasons; otherwise return only `{ "error": "invalid_token" }`.

## 11. Role middleware assumes authentication happened correctly

**Category:** Authorization robustness  
**Severity:** Medium  

**Issue:** `requireRole` reads `req.user` but does not handle missing authentication context clearly.

**Exploit scenario:** If a route accidentally attaches `requireRole` without `authenticateJWT`, the middleware returns a 403 rather than a clear 401. This hides route configuration mistakes and makes authorization behavior inconsistent.

**Fix:** Have role middleware explicitly check for `req.user`. If absent, return 401. If present but missing the role, return 403.

## 12. 403 response has no structured body

**Category:** Error handling / API consistency  
**Severity:** Low  

**Issue:** `res.sendStatus(403)` provides no structured response body.

**Exploit scenario:** This is not the main vulnerability, but it makes clients handle errors inconsistently and can make authorization failures harder to audit.

**Fix:** Return a stable body such as `{ "error": "forbidden" }`. Keep details generic and log specifics server-side.