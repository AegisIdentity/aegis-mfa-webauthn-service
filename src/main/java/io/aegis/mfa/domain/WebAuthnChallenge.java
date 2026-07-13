package io.aegis.mfa.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * A short-lived, single-use WebAuthn challenge issued at the start of a registration or assertion
 * ceremony and consumed when the browser completes it. Persisted (rather than held in memory) so the
 * ceremony survives across service instances and its expiry/one-time-use is enforced server-side —
 * the anti-replay backbone of WebAuthn. At most one live challenge per (tenant, subject, type).
 */
@Entity
@Table(name = "webauthn_challenge")
public class WebAuthnChallenge {

    public enum Type { REGISTRATION, ASSERTION }

    @Id
    @Column(nullable = false, updatable = false)
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId;

    @Column(nullable = false)
    private String subject;

    /** Base64url-encoded random challenge bytes. */
    @Column(nullable = false, length = 128)
    private String challenge;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private Type type;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    protected WebAuthnChallenge() {
    }

    public WebAuthnChallenge(String tenantId, String subject, String challenge, Type type, Instant expiresAt) {
        this.id = UUID.randomUUID();
        this.tenantId = tenantId;
        this.subject = subject;
        this.challenge = challenge;
        this.type = type;
        this.expiresAt = expiresAt;
    }

    public UUID getId() {
        return id;
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getSubject() {
        return subject;
    }

    public String getChallenge() {
        return challenge;
    }

    public Type getType() {
        return type;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public boolean isExpired(Instant now) {
        return now.isAfter(expiresAt);
    }
}
