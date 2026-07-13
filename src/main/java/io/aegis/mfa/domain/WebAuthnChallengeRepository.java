package io.aegis.mfa.domain;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface WebAuthnChallengeRepository extends JpaRepository<WebAuthnChallenge, UUID> {

    Optional<WebAuthnChallenge> findFirstByTenantIdAndSubjectAndTypeOrderByExpiresAtDesc(
            String tenantId, String subject, WebAuthnChallenge.Type type);

    void deleteByTenantIdAndSubjectAndType(String tenantId, String subject, WebAuthnChallenge.Type type);
}
