package io.aegis.mfa.service;

import io.aegis.mfa.config.MfaProperties;
import io.aegis.mfa.domain.WebAuthnTenantConfig;
import io.aegis.mfa.domain.WebAuthnTenantConfigRepository;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Per-tenant WebAuthn RP configuration: the setup surface a tenant uses to describe its OWN application
 * (Model B). {@link #effective(String)} returns the stored row or a transient default seeded from the
 * global {@link MfaProperties}; {@link #update} upserts + validates.
 *
 * <p>Consumed by tenant-app-facing endpoints (future runtime). The Aegis-hosted ceremony
 * ({@code startRegistration}/{@code verifyAssertion}) deliberately keeps using the global config.
 */
@Service
public class WebAuthnConfigService {

    static final Set<String> USER_VERIFICATION = Set.of("preferred", "required", "discouraged");
    static final Set<String> AUTHENTICATOR_ATTACHMENT = Set.of("platform", "cross-platform", "any");
    static final Set<String> RESIDENT_KEY = Set.of("required", "preferred", "discouraged");
    static final Set<String> ATTESTATION = Set.of("none", "indirect", "direct");

    private final WebAuthnTenantConfigRepository repository;
    private final MfaProperties props;

    public WebAuthnConfigService(WebAuthnTenantConfigRepository repository, MfaProperties props) {
        this.repository = repository;
        this.props = props;
    }

    /**
     * The effective config for a tenant: the stored row, or a transient default built from the global
     * {@link MfaProperties} (rpId/rpName/origins) with the documented policy defaults when absent. The
     * returned default is <em>not</em> persisted.
     */
    @Transactional(readOnly = true)
    public WebAuthnTenantConfig effective(String tenantId) {
        return repository.findById(tenantId).orElseGet(() -> defaults(tenantId));
    }

    private WebAuthnTenantConfig defaults(String tenantId) {
        MfaProperties.WebAuthn global = props.getWebauthn();
        WebAuthnTenantConfig cfg = new WebAuthnTenantConfig(tenantId);
        cfg.setRpId(global.getRpId());
        cfg.setRpName(global.getRpName());
        cfg.setOrigins(global.getAllowedOrigins());
        cfg.setUserVerification("preferred");
        cfg.setAuthenticatorAttachment("any");
        cfg.setResidentKey("preferred");
        cfg.setAttestation("none");
        cfg.setEnabled(true);
        return cfg;
    }

    /**
     * Upsert a tenant's config after validation. rpId must be non-blank; every origin must look like an
     * origin/URL or an {@code android:apk-key-hash} (lenient — only blanks are rejected); the four policy
     * fields must each be in their allowed set. Any violation throws
     * {@link MfaExceptions.InvalidVerificationException} (→ 400).
     */
    @Transactional
    public WebAuthnTenantConfig update(String tenantId, String rpId, String rpName, List<String> origins,
                                       String userVerification, String authenticatorAttachment,
                                       String residentKey, String attestation, boolean enabled) {
        String cleanRpId = rpId == null ? "" : rpId.strip();
        if (cleanRpId.isBlank()) {
            throw new MfaExceptions.InvalidVerificationException("rpId must not be blank");
        }
        String cleanRpName = (rpName == null || rpName.isBlank()) ? cleanRpId : rpName.strip();

        List<String> cleanOrigins = (origins == null ? List.<String>of() : origins).stream()
                .map(o -> o == null ? "" : o.strip())
                .filter(o -> !o.isEmpty())
                .toList();
        for (String origin : (origins == null ? List.<String>of() : origins)) {
            if (origin == null || origin.isBlank()) {
                throw new MfaExceptions.InvalidVerificationException("origins must not contain blanks");
            }
            if (!looksLikeOrigin(origin.strip())) {
                throw new MfaExceptions.InvalidVerificationException("not a valid origin: " + origin.strip());
            }
        }

        String uv = normalize(userVerification, "preferred");
        String att = normalize(authenticatorAttachment, "any");
        String rk = normalize(residentKey, "preferred");
        String attn = normalize(attestation, "none");
        require(USER_VERIFICATION, uv, "userVerification");
        require(AUTHENTICATOR_ATTACHMENT, att, "authenticatorAttachment");
        require(RESIDENT_KEY, rk, "residentKey");
        require(ATTESTATION, attn, "attestation");

        WebAuthnTenantConfig cfg = repository.findById(tenantId)
                .orElseGet(() -> new WebAuthnTenantConfig(tenantId));
        cfg.setRpId(cleanRpId);
        cfg.setRpName(cleanRpName);
        cfg.setOrigins(cleanOrigins);
        cfg.setUserVerification(uv);
        cfg.setAuthenticatorAttachment(att);
        cfg.setResidentKey(rk);
        cfg.setAttestation(attn);
        cfg.setEnabled(enabled);
        cfg.touch();
        return repository.save(cfg);
    }

    private static String normalize(String value, String fallback) {
        return (value == null || value.isBlank()) ? fallback : value.strip().toLowerCase(Locale.ROOT);
    }

    private static void require(Set<String> allowed, String value, String field) {
        if (!allowed.contains(value)) {
            throw new MfaExceptions.InvalidVerificationException(field + " must be one of " + allowed);
        }
    }

    /**
     * Lenient origin sanity-check: an http(s) URL/origin, or an {@code android:apk-key-hash:...}. We only
     * reject clearly-wrong values; full RP-id/origin registrable-suffix checking is a browser concern.
     */
    private static boolean looksLikeOrigin(String origin) {
        if (origin.startsWith("android:apk-key-hash:")) {
            return origin.length() > "android:apk-key-hash:".length();
        }
        String lower = origin.toLowerCase(Locale.ROOT);
        if (lower.startsWith("http://") || lower.startsWith("https://")) {
            return origin.length() > lower.indexOf("://") + 3;
        }
        return false;
    }
}
