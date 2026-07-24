package io.aegis.mfa.domain;

import io.aegis.mfa.crypto.EncryptedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import java.util.UUID;

/**
 * A user's TOTP (RFC 6238) authenticator enrolment. At most one per (tenant, subject). Created
 * <em>disabled</em> at enrolment and flipped to enabled only after the user proves possession by
 * entering a valid code (confirm-before-activate), so a half-finished enrolment never gates login.
 *
 * <p>The shared secret is sensitive and is encrypted at rest with AES-256-GCM via
 * {@link EncryptedStringConverter} (H5); the key is supplied from a secret manager in non-dev. It is
 * never returned by any read API after enrolment.
 */
@Entity
@Table(name = "totp_credential",
        uniqueConstraints = @UniqueConstraint(name = "uq_totp_tenant_subject", columnNames = {"tenant_id", "subject"}))
public class TotpCredential {

    @Id
    @Column(nullable = false, updatable = false)
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId;

    @Column(nullable = false)
    private String subject;

    /** Base32-encoded shared secret (the authenticator-app format), AES-256-GCM encrypted at rest (H5). */
    @Convert(converter = EncryptedStringConverter.class)
    @Column(name = "secret_base32", nullable = false, length = 255)
    private String secretBase32;

    @Column(nullable = false)
    private boolean enabled;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    protected TotpCredential() {
    }

    public TotpCredential(String tenantId, String subject, String secretBase32) {
        this.id = UUID.randomUUID();
        this.tenantId = tenantId;
        this.subject = subject;
        this.secretBase32 = secretBase32;
        this.enabled = false;
        this.createdAt = Instant.now();
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

    public String getSecretBase32() {
        return secretBase32;
    }

    public void setSecretBase32(String secretBase32) {
        this.secretBase32 = secretBase32;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getLastUsedAt() {
        return lastUsedAt;
    }

    public void setLastUsedAt(Instant lastUsedAt) {
        this.lastUsedAt = lastUsedAt;
    }
}
