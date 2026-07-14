package io.aegis.mfa.web;

import io.aegis.mfa.domain.TotpCredential;
import io.aegis.mfa.domain.WebAuthnCredential;
import jakarta.validation.constraints.NotBlank;
import java.time.Instant;
import java.util.List;

/** Request/response shapes for the MFA API. Nothing here ever carries a TOTP secret or COSE key. */
public final class MfaDtos {

    private MfaDtos() {
    }

    /** The enrolment challenge for a TOTP authenticator: the secret to store and the otpauth URI (QR). */
    public record TotpEnrollResponse(String secret, String otpauthUri) {
    }

    public record CodeRequest(@NotBlank String code) {
    }

    /** A caller's enrolled factors. {@code totp} is null when not enrolled. */
    public record FactorsResponse(TotpView totp, List<PasskeyView> passkeys) {
    }

    public record TotpView(boolean enabled, Instant createdAt, Instant lastUsedAt) {
        static TotpView of(TotpCredential c) {
            return c == null ? null : new TotpView(c.isEnabled(), c.getCreatedAt(), c.getLastUsedAt());
        }
    }

    public record PasskeyView(String id, String label, String aaguid, Instant createdAt, Instant lastUsedAt) {
        static PasskeyView of(WebAuthnCredential c) {
            return new PasskeyView(c.getId().toString(), c.getLabel(), c.getAaguid(),
                    c.getCreatedAt(), c.getLastUsedAt());
        }
    }

    /** Finish a passkey registration. The two byte fields are base64url (the browser's ArrayBuffers). */
    public record PasskeyFinishRequest(
            @NotBlank String attestationObject,
            @NotBlank String clientDataJSON,
            String label) {
    }

    // --- Internal step-up (server-to-server, called by the authorization-server) ---

    /** Whether a user has any usable MFA factor, and which methods. */
    public record StepUpStatus(boolean enrolled, List<String> methods) {
    }

    public record TotpValidateRequest(
            @NotBlank String tenant,
            @NotBlank String subject,
            @NotBlank String code) {
    }

    /** Force-enrol a TOTP secret on a user's behalf (the AS drives first-time enrolment during login). */
    public record InternalEnrollRequest(
            @NotBlank String tenant,
            @NotBlank String subject,
            @NotBlank String account) {
    }

    public record ValidateResponse(boolean valid) {
    }
}
