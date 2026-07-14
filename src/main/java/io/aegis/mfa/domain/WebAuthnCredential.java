package io.aegis.mfa.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import java.util.UUID;

/**
 * A registered WebAuthn/FIDO2 passkey. The credential id is globally unique (a browser must never let
 * one authenticator register the same credential twice); the COSE public key and signature counter are
 * what later assertions are verified against. Tenant + subject scope it to its owner.
 */
@Entity
@Table(name = "webauthn_credential",
        uniqueConstraints = @UniqueConstraint(name = "uq_webauthn_credential_id", columnNames = "credential_id"))
public class WebAuthnCredential {

    @Id
    @Column(nullable = false, updatable = false)
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId;

    @Column(nullable = false)
    private String subject;

    /** Base64url-encoded credential id (the authenticator's handle for this key). */
    @Column(name = "credential_id", nullable = false, length = 512)
    private String credentialId;

    /**
     * CBOR-encoded COSE public key, as extracted from the attestation during registration. Stored as
     * {@code bytea} (small binary), NOT a large object — {@code @Lob byte[]} maps to a Postgres {@code oid}
     * which can only be read inside a transaction (fails auto-commit reads like the factors list) and
     * leaks orphaned large objects on delete.
     */
    @Column(name = "public_key_cose", nullable = false, columnDefinition = "bytea")
    private byte[] publicKeyCose;

    @Column(name = "sign_count", nullable = false)
    private long signCount;

    /** Human label the user gives the passkey (e.g. "MacBook Touch ID"). */
    @Column(nullable = false, length = 120)
    private String label;

    /** Authenticator model identifier (AAGUID), for display; may be all-zero for privacy. */
    @Column(length = 64)
    private String aaguid;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    protected WebAuthnCredential() {
    }

    public WebAuthnCredential(String tenantId, String subject, String credentialId,
                             byte[] publicKeyCose, long signCount, String label, String aaguid) {
        this.id = UUID.randomUUID();
        this.tenantId = tenantId;
        this.subject = subject;
        this.credentialId = credentialId;
        this.publicKeyCose = publicKeyCose;
        this.signCount = signCount;
        this.label = label;
        this.aaguid = aaguid;
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

    public String getCredentialId() {
        return credentialId;
    }

    public byte[] getPublicKeyCose() {
        return publicKeyCose;
    }

    public long getSignCount() {
        return signCount;
    }

    public void setSignCount(long signCount) {
        this.signCount = signCount;
    }

    public String getLabel() {
        return label;
    }

    public String getAaguid() {
        return aaguid;
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
