package io.aegis.mfa.domain;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

public interface WebAuthnChallengeRepository extends JpaRepository<WebAuthnChallenge, UUID> {

    Optional<WebAuthnChallenge> findFirstByTenantIdAndSubjectAndTypeOrderByExpiresAtDesc(
            String tenantId, String subject, WebAuthnChallenge.Type type);

    void deleteByTenantIdAndSubjectAndType(String tenantId, String subject, WebAuthnChallenge.Type type);

    /**
     * Garbage-collect abandoned/expired challenges of BOTH types (H7). Assertion challenges in particular
     * are otherwise only removed on a matching verify, so abandoned ceremonies would accumulate forever.
     */
    @Modifying
    @Query("delete from WebAuthnChallenge c where c.expiresAt < ?1")
    int deleteByExpiresAtBefore(Instant cutoff);
}
