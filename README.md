# aegis-mfa-webauthn-service

Passkeys (WebAuthn/FIDO2), TOTP, and step-up MFA.

**Maturity: scaffold.** Buildable, secured resource-server skeleton — health endpoint, a protected
placeholder API, and the shared `aegis-security-commons` hardening baseline. Feature work goes here;
the intended contract is in
[`aegis-platform-docs/architecture/SERVICE-CATALOG.md`](../aegis-platform-docs/architecture/SERVICE-CATALOG.md).

- Port: `9103` · Required scope for `/api/**`: `mfa:admin`
- Build: `./mvnw verify` (needs `aegis-platform-parent` + `aegis-platform-commons` installed to `~/.m2` first)
