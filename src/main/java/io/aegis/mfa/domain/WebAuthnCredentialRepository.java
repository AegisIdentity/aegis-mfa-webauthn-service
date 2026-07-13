package io.aegis.mfa.domain;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface WebAuthnCredentialRepository extends JpaRepository<WebAuthnCredential, UUID> {

    List<WebAuthnCredential> findByTenantIdAndSubjectOrderByCreatedAtDesc(String tenantId, String subject);

    Optional<WebAuthnCredential> findByTenantIdAndSubjectAndId(String tenantId, String subject, UUID id);

    Optional<WebAuthnCredential> findByCredentialId(String credentialId);

    boolean existsByTenantIdAndSubject(String tenantId, String subject);
}
