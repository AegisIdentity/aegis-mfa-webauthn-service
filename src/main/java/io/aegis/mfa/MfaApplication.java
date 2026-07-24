package io.aegis.mfa;

import io.aegis.mfa.config.MfaProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

/** Passkeys (WebAuthn/FIDO2), TOTP, and step-up MFA.
 *
 * <p>Self-service factor enrolment (TOTP + passkeys) for the end-user portal, plus server-to-server
 * step-up verification consumed by the authorization-server during login. See
 * aegis-platform-docs/architecture/SERVICE-CATALOG.md for the intended contract. */
@SpringBootApplication
@EnableScheduling
@EnableConfigurationProperties(MfaProperties.class)
public class MfaApplication {
    public static void main(String[] args) {
        SpringApplication.run(MfaApplication.class, args);
    }
}
