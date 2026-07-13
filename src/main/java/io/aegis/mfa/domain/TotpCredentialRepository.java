package io.aegis.mfa.domain;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TotpCredentialRepository extends JpaRepository<TotpCredential, java.util.UUID> {

    Optional<TotpCredential> findByTenantIdAndSubject(String tenantId, String subject);

    void deleteByTenantIdAndSubject(String tenantId, String subject);
}
