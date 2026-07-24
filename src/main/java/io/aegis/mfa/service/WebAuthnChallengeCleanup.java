package io.aegis.mfa.service;

import io.aegis.mfa.domain.WebAuthnChallengeRepository;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Scheduled garbage-collection of expired WebAuthn challenges (H7). Registration challenges are cleaned
 * on the next ceremony start, but abandoned ASSERTION challenges are only removed on a matching verify —
 * so without this job they leak forever (storage-exhaustion DoS + stale material past the 300s TTL). This
 * deletes every challenge (either type) whose {@code expiresAt} is in the past.
 */
@Component
public class WebAuthnChallengeCleanup {

    private static final Logger log = LoggerFactory.getLogger(WebAuthnChallengeCleanup.class);

    private final WebAuthnChallengeRepository challenges;

    public WebAuthnChallengeCleanup(WebAuthnChallengeRepository challenges) {
        this.challenges = challenges;
    }

    /** Sweep expired challenges every 5 minutes (initial delay lets the app finish starting). */
    @Scheduled(initialDelayString = "PT1M", fixedDelayString = "PT5M")
    @Transactional
    public void purgeExpired() {
        int removed = challenges.deleteByExpiresAtBefore(Instant.now());
        if (removed > 0) {
            log.debug("purged {} expired WebAuthn challenge(s)", removed);
        }
    }
}
