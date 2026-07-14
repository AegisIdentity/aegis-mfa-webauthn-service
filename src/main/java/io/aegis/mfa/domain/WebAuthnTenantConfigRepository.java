package io.aegis.mfa.domain;

import org.springframework.data.jpa.repository.JpaRepository;

/** Per-tenant WebAuthn RP config, keyed by {@code tenantId} (String id). */
public interface WebAuthnTenantConfigRepository extends JpaRepository<WebAuthnTenantConfig, String> {
}
