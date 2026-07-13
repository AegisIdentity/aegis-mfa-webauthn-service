package io.aegis.mfa;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Passkeys (WebAuthn/FIDO2), TOTP, and step-up MFA.
 *
 * <p>Maturity: scaffold. This is a buildable, secured resource-server skeleton (health + a
 * protected info endpoint + the shared hardening baseline) ready for feature work. See
 * aegis-platform-docs/architecture/SERVICE-CATALOG.md for the intended contract. */
@SpringBootApplication
public class MfaApplication {
    public static void main(String[] args) {
        SpringApplication.run(MfaApplication.class, args);
    }
}
