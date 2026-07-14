package io.aegis.mfa.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

/**
 * Per-tenant WebAuthn/passkey Relying-Party configuration — the setup surface a tenant uses to describe
 * its <em>own</em> application (Model B), keyed by {@code tenantId}. Absence of a row means "use the
 * global {@link io.aegis.mfa.config.MfaProperties} defaults". Field-access JPA (the {@code List}
 * accessors for {@code origins} are helpers for the API, not mapped properties — the column is CSV).
 *
 * <p><b>Not yet wired into the Aegis-hosted ceremony:</b> {@code startRegistration}/{@code verifyAssertion}
 * keep using the global config. This row is consumed by tenant-app-facing endpoints (future runtime).
 */
@Entity
@Table(name = "webauthn_tenant_config")
public class WebAuthnTenantConfig {

    @Id
    @Column(name = "tenant_id", nullable = false, updatable = false, length = 64)
    private String tenantId;

    @Column(name = "rp_id", nullable = false, length = 255)
    private String rpId;

    @Column(name = "rp_name", nullable = false, length = 255)
    private String rpName;

    /** Allowed origins, CSV. The {@code List} accessors below split/join; the column stays a single string. */
    @Column(name = "origins", nullable = false, length = 2048)
    private String origins;

    @Column(name = "user_verification", nullable = false, length = 16)
    private String userVerification = "preferred";

    @Column(name = "authenticator_attachment", nullable = false, length = 16)
    private String authenticatorAttachment = "any";

    @Column(name = "resident_key", nullable = false, length = 16)
    private String residentKey = "preferred";

    @Column(name = "attestation", nullable = false, length = 16)
    private String attestation = "none";

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    protected WebAuthnTenantConfig() {
    }

    public WebAuthnTenantConfig(String tenantId) {
        this.tenantId = tenantId;
    }

    public void touch() {
        this.updatedAt = Instant.now();
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getRpId() {
        return rpId;
    }

    public void setRpId(String rpId) {
        this.rpId = rpId;
    }

    public String getRpName() {
        return rpName;
    }

    public void setRpName(String rpName) {
        this.rpName = rpName;
    }

    public List<String> getOrigins() {
        return (origins == null || origins.isBlank())
                ? List.of()
                : Arrays.stream(origins.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
    }

    public void setOrigins(List<String> value) {
        this.origins = (value == null || value.isEmpty())
                ? ""
                : String.join(",", value.stream().map(String::trim).filter(s -> !s.isEmpty()).toList());
    }

    public String getUserVerification() {
        return userVerification;
    }

    public void setUserVerification(String userVerification) {
        this.userVerification = userVerification;
    }

    public String getAuthenticatorAttachment() {
        return authenticatorAttachment;
    }

    public void setAuthenticatorAttachment(String authenticatorAttachment) {
        this.authenticatorAttachment = authenticatorAttachment;
    }

    public String getResidentKey() {
        return residentKey;
    }

    public void setResidentKey(String residentKey) {
        this.residentKey = residentKey;
    }

    public String getAttestation() {
        return attestation;
    }

    public void setAttestation(String attestation) {
        this.attestation = attestation;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
