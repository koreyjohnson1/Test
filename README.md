# Senior OAuth2 Take-Home Assessment

This repository implements a small OAuth2/API security assessment in Node.js.

It includes:

- A self-contained JWT validation module using RS256 and JWKS.
- Typed JWT validation errors.
- JWKS caching with bounded TTL behavior.
- Controlled JWKS forced-refresh behavior for unknown `kid` values.
- Express authorization middleware for authentication, scopes, roles, and ownership checks.
- Tests for JWT validation and protected document routes.
- Written protocol/security responses in `RESPONSES.md`.
- Code review findings in `REVIEW.md`.

## Requirements

- Node.js 18+
- npm

Node 18+ is required because the JWKS client uses the built-in `fetch` API.

## Install

```bash
npm install