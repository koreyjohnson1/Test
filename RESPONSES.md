# Written Responses

## 1. Redirect URI validation during authorization code exchange

Yes, the token exchange endpoint should validate the `redirect_uri` when one was used in the authorization request. I would treat the finding as valid, but I would not automatically call it "critical" without understanding the rest of the implementation.

In the Authorization Code flow, the authorization code is bound to the client, redirect URI, and authorization request. During token exchange, the authorization server should verify that the `redirect_uri` exactly matches the original value if it was included in the authorization request. This prevents authorization code substitution or interception scenarios where a code issued through one redirect path is redeemed through another.

PKCE reduces the risk because the attacker also needs the correct `code_verifier`, but PKCE does not remove the need to bind the code to the redirect URI. For it to be exploitable, an attacker would need some way to obtain or inject an authorization code and redeem it through a mismatched exchange path. I would fix it by storing the original redirect URI with the authorization code and requiring an exact match at token exchange time.

## 2. Unknown `kid` JWKS refetch attack

If the validator refetches JWKS every time it sees an unknown `kid`, an attacker can send a stream of forged JWTs with random `kid` values. The attacker does not need to break RS256 or produce a valid signature. They only need to force the resource server into repeated network calls to the JWKS endpoint.

The impact is denial of service. The API spends time waiting on JWKS fetches, consumes outbound network capacity, and can also overload the authorization server. If many application instances do this at the same time, a small amount of attacker traffic can create a much larger amount of internal traffic.

The mitigation is to cache JWKS by issuer or JWKS URI with a bounded TTL, use the cached keys for known kids, and only force-refresh once when an unknown `kid` appears. Forced refreshes should be rate-limited or debounced per JWKS URI. Unknown kids can also be negative-cached briefly so the same fake kid does not trigger repeated refresh attempts. If the key is still unknown after a controlled refresh, the validator should fail closed with `UnknownKeyError`.

## 3. Accepting Service B tokens at Service A

Service A should not accept access tokens whose `aud` claim identifies Service B. The audience claim defines the intended resource server. If Service A accepts a token minted for Service B, then a token stolen from or legitimately issued for one service becomes replayable against another service. That breaks audience isolation.

This is a confused-deputy problem. The user may have authorized Service B for one set of capabilities, but Service A is now treating that same token as proof that the user authorized access to Service A. Scopes alone are not enough because scopes are meaningful only in the context of the intended audience.

The correct pattern is token exchange or an on-behalf-of flow. Service A should receive the user token, validate it for the proper audience, and then exchange it with the authorization server for a new token intended for the downstream service. The new token should have the downstream service as `aud`, a narrow set of scopes, and an explicit delegation chain.

This keeps each resource server responsible for accepting only tokens intended for it, while still allowing user delegation across services.

## 4. Five-minute vs sixty-minute access tokens

A 5-minute access token limits the damage from token theft. If an attacker steals the token, the useful window is short. It also improves revocation latency because disabled users or changed permissions stop working sooner even without introspection. The tradeoff is operational churn: mobile clients refresh more often, intermittent connectivity causes more failed requests, and the authorization infrastructure sees more refresh traffic.

A 60-minute access token improves user experience and reduces refresh-token churn. It is friendlier for mobile clients with poor connectivity and reduces load on the token endpoint. The security tradeoff is a much larger compromise window. A stolen token remains useful longer, and account deactivation or permission changes may not take effect until the token expires unless the API adds server-side revocation checks.

My default recommendation is 5 to 15 minutes for sensitive APIs, paired with refresh token rotation and reuse detection. I would move closer to 60 minutes only for lower-risk APIs, heavily offline mobile scenarios, or systems with strong centralized introspection/revocation on every request.

## 5. Deactivated user with still-valid access token

There are several mechanisms to prevent a deactivated user from continuing to use an otherwise valid JWT.

The simplest mechanism is short access-token lifetime. This limits the exposure window, but it does not provide immediate revocation. The user may still have access until expiration.

Another option is token introspection on each request. This gives near-real-time control because the authorization server can reject tokens for deactivated users. The tradeoff is added latency, dependency on the auth service, and reduced availability if introspection is down.

A third option is a revocation list or denylist keyed by `jti` or session ID. This gives targeted revocation, but the API must check shared state on each request or maintain a synchronized cache. It also requires every token to contain a stable identifier.

Another option is a user status or session version check. The token contains a `session_version`, `auth_time`, or similar claim, and the API compares it to cached user state. Deactivating the user increments the version or marks the user disabled. This gives fast revocation without full token introspection on every request.

For 50,000 active users, I would recommend short-lived access tokens, refresh token rotation, and a cached user-status/session-version check for sensitive APIs. That keeps most requests local and fast while still allowing account deactivation to take effect quickly. The cache should have a short TTL and event-driven invalidation when users are deactivated.

## 6. SHA-256 vs bcrypt or Argon2 for refresh tokens

For password storage, SHA-256 is not enough because passwords are low entropy and attackers can brute force them quickly. bcrypt and Argon2 are intentionally slow and make offline guessing expensive.

Refresh tokens should be different. A refresh token should be a high-entropy, randomly generated opaque secret, not a human-chosen value. If the token has at least 128 to 256 bits of randomness, storing an HMAC-SHA256 hash of it can be acceptable because there is no practical dictionary to brute force.

I would store refresh tokens as `HMAC-SHA256(server_pepper, token)` rather than plain SHA-256. The pepper protects stored hashes if the database is leaked but the application secret is not. I would also rotate refresh tokens on every use and detect reuse of old tokens.

I would use Argon2 only if refresh tokens were not guaranteed to be high entropy, which should not be the case. The better fix is to generate strong random tokens and store only a keyed hash.

## 7. Tenant isolation model

I would include tenant identity in the token, for example `tenant_id`, and enforce tenant isolation in the application and data access layer. The token should identify the tenant context, but the API must still verify that every resource being read or modified belongs to that tenant.

I would not model every tenant permission as OAuth scopes. Scopes are better for coarse-grained API capabilities such as `documents:read` or `documents:write`. Encoding every tenant relationship into scopes creates large tokens and makes permission changes difficult.

I also would not leave tenant context completely out of the token unless every request uses a centralized authorization lookup. That can be secure, but it adds latency and makes the API more dependent on the authorization service.

My recommendation is: token contains `sub`, `aud`, `iss`, coarse scopes, roles, and `tenant_id`; API validates the token; route or service layer loads the resource; data access enforces `resource.tenant_id === token.tenant_id`. For cross-tenant admins, I would require an explicit elevated role and audit those actions separately.