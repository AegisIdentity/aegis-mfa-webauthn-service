package io.aegis.mfa.service;

import io.aegis.mfa.domain.WebAuthnAuditEvent;
import io.aegis.mfa.domain.WebAuthnAuditEventRepository;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Best-effort passkey audit trail. {@link #record} never throws and never breaks the primary op — a
 * failed write is logged at WARN and swallowed. {@link #recent} returns a tenant's events newest-first.
 */
@Service
public class WebAuthnAuditService {

    private static final Logger log = LoggerFactory.getLogger(WebAuthnAuditService.class);

    private static final int DEFAULT_LIMIT = 50;
    private static final int MAX_LIMIT = 200;

    private final WebAuthnAuditEventRepository repository;

    public WebAuthnAuditService(WebAuthnAuditEventRepository repository) {
        this.repository = repository;
    }

    /**
     * Record one passkey event. Best-effort: any failure is logged and swallowed so the caller's primary
     * operation is never affected. Runs in its own transaction ({@code REQUIRES_NEW}) so an audit write
     * failure cannot mark the caller's transaction rollback-only.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(String tenantId, String subject, String action,
                       String credentialId, String aaguid, String detail) {
        try {
            String tenant = (tenantId == null || tenantId.isBlank()) ? "*" : tenantId;
            repository.save(new WebAuthnAuditEvent(tenant, subject, action, credentialId, aaguid, detail));
        } catch (RuntimeException ex) {
            log.warn("webauthn audit write failed (action={}, tenant={}): {}", action, tenantId, ex.toString());
        }
    }

    /** A tenant's recent events, newest first. {@code limit} clamps to [1, {@value #MAX_LIMIT}] (default {@value #DEFAULT_LIMIT}). */
    @Transactional(readOnly = true)
    public List<WebAuthnAuditEvent> recent(String tenantId, Integer limit) {
        int clamped = (limit == null || limit <= 0) ? DEFAULT_LIMIT : Math.min(limit, MAX_LIMIT);
        return repository.findByTenantIdOrderByAtDesc(tenantId, PageRequest.of(0, clamped));
    }
}
