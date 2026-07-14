package io.aegis.mfa.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * An append-only record of a passkey lifecycle event, tenant-scoped for admin visibility. Written
 * best-effort (a failed audit must never break the primary op), so a missing row is a soft failure and
 * never a broken ceremony. {@code subject}/{@code credentialId}/{@code aaguid}/{@code detail} are
 * nullable because a failed assertion may not resolve to a known user or credential.
 */
@Entity
@Table(name = "webauthn_audit_event",
        indexes = @Index(name = "ix_webauthn_audit_tenant", columnList = "tenant_id"))
public class WebAuthnAuditEvent {

    /** The passkey lifecycle actions we record. */
    public static final String PASSKEY_REGISTERED = "PASSKEY_REGISTERED";
    public static final String PASSKEY_AUTHENTICATED = "PASSKEY_AUTHENTICATED";
    public static final String PASSKEY_REMOVED = "PASSKEY_REMOVED";
    public static final String PASSKEY_ASSERT_FAILED = "PASSKEY_ASSERT_FAILED";

    @Id
    @Column(nullable = false, updatable = false)
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId;

    @Column(name = "subject")
    private String subject;

    @Column(name = "action", nullable = false, length = 32)
    private String action;

    @Column(name = "credential_id", length = 512)
    private String credentialId;

    @Column(name = "aaguid", length = 64)
    private String aaguid;

    @Column(name = "detail", length = 512)
    private String detail;

    @Column(name = "at", nullable = false)
    private Instant at;

    protected WebAuthnAuditEvent() {
    }

    public WebAuthnAuditEvent(String tenantId, String subject, String action,
                              String credentialId, String aaguid, String detail) {
        this.id = UUID.randomUUID();
        this.tenantId = tenantId;
        this.subject = subject;
        this.action = action;
        this.credentialId = credentialId;
        this.aaguid = aaguid;
        this.detail = detail;
        this.at = Instant.now();
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

    public String getAction() {
        return action;
    }

    public String getCredentialId() {
        return credentialId;
    }

    public String getAaguid() {
        return aaguid;
    }

    public String getDetail() {
        return detail;
    }

    public Instant getAt() {
        return at;
    }
}
