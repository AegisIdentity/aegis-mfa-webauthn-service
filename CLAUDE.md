# aegis-mfa-webauthn-service — working notes

Passkeys (WebAuthn/FIDO2), TOTP, and step-up MFA.  **Maturity: scaffold** (skeleton, not feature-complete).

## What this is
A Spring Boot 4.1 / Java 21 OAuth2 **resource server** skeleton in the Aegis polyrepo. Package root:
`io.aegis.mfa`. Security lives in `SecurityConfig` (uses `io.aegis.commons.security.SecurityHardening`).

## Non-negotiables (do not regress)
- Default-deny: every new endpoint stays denied until an explicit `authorizeHttpRequests` rule + a
  **negative test** ("no token -> 401", "wrong scope -> 403") is added.
- Keep the shared hardening baseline applied. Validate JWTs against the authorization-server issuer.
- All persistent data must be **tenant-scoped** (see ARCHITECTURE.md §5). No cross-tenant reads.

## Build / test
`./mvnw verify` — resolves `aegis-platform-parent` and `aegis-security-commons` from `~/.m2`
(build `aegis-platform-bom` and `aegis-platform-commons` first).

## Next steps
Implement the endpoints in SERVICE-CATALOG.md, add JPA + Testcontainers integration tests following
the pattern in `aegis-identity-service`, and wire domain events to `aegis-audit-commons`.
