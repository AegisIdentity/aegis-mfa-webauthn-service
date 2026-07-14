package io.aegis.mfa.domain;

import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface WebAuthnAuditEventRepository extends JpaRepository<WebAuthnAuditEvent, UUID> {

    List<WebAuthnAuditEvent> findByTenantIdOrderByAtDesc(String tenantId, Pageable pageable);
}
