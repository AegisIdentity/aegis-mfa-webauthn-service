package io.aegis.mfa.service;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import io.aegis.mfa.config.MfaProperties;
import io.aegis.mfa.domain.WebAuthnAuditEvent;
import io.aegis.mfa.domain.WebAuthnChallenge;
import io.aegis.mfa.domain.WebAuthnChallengeRepository;
import io.aegis.mfa.domain.WebAuthnCredential;
import io.aegis.mfa.domain.WebAuthnCredentialRepository;
import io.aegis.mfa.domain.WebAuthnTenantConfig;
import io.aegis.mfa.web.MfaDtos.AssertOptionsResponse;
import io.aegis.mfa.web.MfaDtos.AssertVerifyResponse;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * WebAuthn/FIDO2 passkey registration, tenant + subject scoped.
 *
 * <p>The Relying Party (rp-id, name, allowed origins) is configured; challenges are minted, persisted
 * with a TTL, and consumed one-time. Registration attestation is verified with <b>webauthn4j</b>
 * (non-strict: attestation trust anchors are not required, which is the normal posture for passkeys
 * that self-attest with {@code none}). The verified COSE credential is stored for later assertions.
 *
 * <p><b>Maturity:</b> registration is fully verified server-side. A live end-to-end round-trip needs a
 * real authenticator in the browser; the assertion (login-with-passkey) runtime is the documented next
 * step — TOTP is the exercisable step-up factor today.
 */
@Service
public class WebAuthnService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();

    private final WebAuthnCredentialRepository credentials;
    private final WebAuthnChallengeRepository challenges;
    private final MfaProperties props;
    private final WebAuthnAuditService audit;
    private final WebAuthnConfigService configService;
    private final WebAuthnManager webAuthnManager;
    private final ObjectConverter objectConverter;

    public WebAuthnService(WebAuthnCredentialRepository credentials,
                           WebAuthnChallengeRepository challenges,
                           MfaProperties props,
                           WebAuthnAuditService audit,
                           WebAuthnConfigService configService) {
        this.credentials = credentials;
        this.challenges = challenges;
        this.props = props;
        this.audit = audit;
        this.configService = configService;
        this.objectConverter = new ObjectConverter();
        // Non-strict: do not require an attestation trust-anchor chain (passkeys use `none`).
        this.webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);
    }

    /**
     * The resolved Relying Party a ceremony runs against: {@code rpId} + {@code rpName} + the set of
     * accepted {@code origins} (what webauthn4j's {@code ServerProperty} checks), plus the four policy
     * knobs that shape the options JSON. Built from the GLOBAL {@link MfaProperties} for the Aegis-hosted
     * self-service flow ({@link #globalRp()}), or from a tenant's own {@link WebAuthnTenantConfig} for the
     * internal tenant-app flow ({@link #effectiveRp(String)}).
     */
    record EffectiveRp(String rpId, String rpName, Set<Origin> origins,
                       String userVerification, String residentKey,
                       String authenticatorAttachment, String attestation) {
    }

    /**
     * The GLOBAL RP, from {@link MfaProperties}. The four policy knobs mirror the values the self-service
     * options have always emitted (residentKey/userVerification "preferred", attestation "none",
     * authenticatorAttachment unconstrained), so the hosted flow is byte-for-byte unchanged.
     */
    private EffectiveRp globalRp() {
        MfaProperties.WebAuthn cfg = props.getWebauthn();
        Set<Origin> origins = cfg.getAllowedOrigins().stream().map(Origin::new).collect(Collectors.toSet());
        return new EffectiveRp(cfg.getRpId(), cfg.getRpName(), origins,
                "preferred", "preferred", "any", "none");
    }

    /**
     * The RP for a tenant-app (embedded) flow: the tenant's OWN {@link WebAuthnTenantConfig} via
     * {@link WebAuthnConfigService#effective(String)}. A blank/{@code "*"} tenant → the global RP, so the
     * hosted flow is unchanged; {@code effective} itself falls back to global-seeded defaults for a tenant
     * without a custom row, so a plain tenant still verifies against {@code localhost}.
     */
    EffectiveRp effectiveRp(String tenantId) {
        if (tenantId == null || tenantId.isBlank() || "*".equals(tenantId)) {
            return globalRp();
        }
        WebAuthnTenantConfig cfg = configService.effective(tenantId);
        Set<Origin> origins = cfg.getOrigins().stream().map(Origin::new).collect(Collectors.toSet());
        return new EffectiveRp(cfg.getRpId(), cfg.getRpName(), origins,
                cfg.getUserVerification(), cfg.getResidentKey(),
                cfg.getAuthenticatorAttachment(), cfg.getAttestation());
    }

    /**
     * Start a registration ceremony: mint + persist a one-time challenge and return
     * PublicKeyCredentialCreationOptions (as a plain JSON-friendly map the browser passes to
     * {@code navigator.credentials.create}).
     */
    @Transactional
    public Map<String, Object> startRegistration(String tenantId, String subject, String userName, String displayName) {
        // Self-service (My Security) — always the GLOBAL RP.
        return startRegistration(tenantId, subject, userName, displayName, globalRp());
    }

    /**
     * Start a registration ceremony against a specific resolved {@link EffectiveRp}. The self-service path
     * passes the GLOBAL rp; the internal tenant-app path passes {@code effectiveRp(tenant)} so the options
     * carry the tenant's own rpId/rpName and authenticator-selection policy.
     */
    @Transactional
    Map<String, Object> startRegistration(String tenantId, String subject, String userName,
                                          String displayName, EffectiveRp rp) {
        byte[] challengeBytes = randomBytes(32);
        String challengeB64 = B64URL.encodeToString(challengeBytes);
        challenges.deleteByTenantIdAndSubjectAndType(tenantId, subject, WebAuthnChallenge.Type.REGISTRATION);
        challenges.save(new WebAuthnChallenge(tenantId, subject, challengeB64,
                WebAuthnChallenge.Type.REGISTRATION,
                Instant.now().plusSeconds(props.getWebauthn().getChallengeTtlSeconds())));

        // User handle: a stable per-user id (the subject) — never PII, so it is safe on the authenticator.
        String userHandle = B64URL.encodeToString(subject.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        List<Map<String, Object>> exclude = credentials
                .findByTenantIdAndSubjectOrderByCreatedAtDesc(tenantId, subject).stream()
                .map(c -> descriptor(c.getCredentialId()))
                .collect(Collectors.toList());

        Map<String, Object> authenticatorSelection = new LinkedHashMap<>();
        authenticatorSelection.put("residentKey", rp.residentKey());
        authenticatorSelection.put("userVerification", rp.userVerification());
        // "any" means "no attachment constraint" — omit the key entirely (a browser rejects "any").
        if (!"any".equals(rp.authenticatorAttachment())) {
            authenticatorSelection.put("authenticatorAttachment", rp.authenticatorAttachment());
        }

        Map<String, Object> options = new LinkedHashMap<>();
        options.put("challenge", challengeB64);
        options.put("rp", Map.of("id", rp.rpId(), "name", rp.rpName()));
        options.put("user", Map.of("id", userHandle, "name", userName, "displayName", displayName));
        options.put("pubKeyCredParams", List.of(
                Map.of("type", "public-key", "alg", -7),    // ES256
                Map.of("type", "public-key", "alg", -257))); // RS256
        options.put("timeout", props.getWebauthn().getChallengeTtlSeconds() * 1000);
        options.put("attestation", rp.attestation());
        options.put("authenticatorSelection", authenticatorSelection);
        options.put("excludeCredentials", exclude);
        return options;
    }

    /**
     * Complete registration: verify the authenticator's attestation against the stored challenge and
     * this RP's origin/id, then persist the credential. {@code attestationObject} and
     * {@code clientDataJSON} are base64url (as the browser encodes the ArrayBuffers).
     */
    @Transactional
    public WebAuthnCredential finishRegistration(String tenantId, String subject,
                                                 String attestationObjectB64, String clientDataJsonB64,
                                                 String label) {
        // Self-service (My Security) — always verify against the GLOBAL RP.
        return finishRegistration(tenantId, subject, attestationObjectB64, clientDataJsonB64, label, globalRp());
    }

    /**
     * Complete registration against a specific resolved {@link EffectiveRp}. The self-service path passes
     * the GLOBAL rp; the internal tenant-app path passes {@code effectiveRp(tenant)} so the attestation is
     * verified against the tenant's own rpId + origins.
     */
    @Transactional
    WebAuthnCredential finishRegistration(String tenantId, String subject,
                                          String attestationObjectB64, String clientDataJsonB64,
                                          String label, EffectiveRp rp) {
        WebAuthnChallenge stored = challenges
                .findFirstByTenantIdAndSubjectAndTypeOrderByExpiresAtDesc(
                        tenantId, subject, WebAuthnChallenge.Type.REGISTRATION)
                .orElseThrow(() -> new MfaExceptions.InvalidVerificationException("no registration in progress"));
        if (stored.isExpired(Instant.now())) {
            challenges.delete(stored);
            throw new MfaExceptions.InvalidVerificationException("registration challenge expired");
        }

        byte[] attestationObject = B64URL_DEC.decode(attestationObjectB64);
        byte[] clientDataJson = B64URL_DEC.decode(clientDataJsonB64);
        Challenge challenge = new DefaultChallenge(B64URL_DEC.decode(stored.getChallenge()));
        ServerProperty serverProperty = new ServerProperty(rp.origins(), rp.rpId(), challenge, null);

        AttestedCredentialData acd;
        long signCount;
        try {
            RegistrationRequest request = new RegistrationRequest(attestationObject, clientDataJson);
            RegistrationData data = webAuthnManager.parse(request);
            RegistrationParameters params = new RegistrationParameters(serverProperty, null, false, true);
            webAuthnManager.verify(data, params);
            acd = data.getAttestationObject().getAuthenticatorData().getAttestedCredentialData();
            signCount = data.getAttestationObject().getAuthenticatorData().getSignCount();
        } catch (RuntimeException ex) {
            throw new MfaExceptions.InvalidVerificationException("attestation verification failed: " + ex.getMessage());
        }

        String credentialId = B64URL.encodeToString(acd.getCredentialId());
        if (credentials.findByCredentialId(credentialId).isPresent()) {
            challenges.delete(stored);
            throw new MfaExceptions.InvalidVerificationException("credential already registered");
        }
        byte[] serializedAcd = new AttestedCredentialDataConverter(objectConverter).convert(acd);
        String aaguid = acd.getAaguid() == null ? null : acd.getAaguid().toString();
        String safeLabel = (label == null || label.isBlank()) ? "Passkey" : label.strip();
        WebAuthnCredential saved = credentials.save(new WebAuthnCredential(
                tenantId, subject, credentialId, serializedAcd, signCount, safeLabel, aaguid));
        challenges.delete(stored);
        audit.record(tenantId, subject, WebAuthnAuditEvent.PASSKEY_REGISTERED, credentialId, aaguid, saved.getLabel());
        return saved;
    }

    /**
     * Begin a usernameless (discoverable-credential) passkey login. We do not yet know which user is
     * signing in, so the challenge is persisted with a placeholder subject ("*") and the given tenant
     * (or "*" when blank) — the real (tenant, subject) is resolved from the credential at verify time.
     * The saved entity's UUID id is the opaque {@code challengeId} the browser echoes back.
     */
    @Transactional
    public AssertOptionsResponse startAssertion(String tenant) {
        String tenantId = (tenant == null || tenant.isBlank()) ? "*" : tenant.strip();
        // Resolve the RP from the tenant's own config; a blank/"*" tenant → global defaults (unchanged
        // hosted behaviour). A custom-config tenant gets its own rpId + userVerification in the options.
        EffectiveRp rp = effectiveRp(tenantId);
        byte[] challengeBytes = randomBytes(32);
        String challengeB64 = B64URL.encodeToString(challengeBytes);
        WebAuthnChallenge saved = challenges.save(new WebAuthnChallenge(
                tenantId, "*", challengeB64, WebAuthnChallenge.Type.ASSERTION,
                Instant.now().plusSeconds(props.getWebauthn().getChallengeTtlSeconds())));
        return new AssertOptionsResponse(
                saved.getId().toString(),
                challengeB64,
                rp.rpId(),
                props.getWebauthn().getChallengeTtlSeconds() * 1000,
                rp.userVerification(),
                List.of());
    }

    /**
     * Verify a passkey assertion (the {@code navigator.credentials.get} response) against the stored
     * one-time challenge and this RP's origin/id, using webauthn4j. Any failure — missing/expired
     * challenge, unknown credential, bad signature, replayed counter, wrong origin/rpId — returns
     * {@code valid:false} and never leaks a reason (a failed assertion is never a 500).
     *
     * <p>On success the signature counter is advanced, the challenge is consumed (one-time), and the
     * credential's owning (tenant, subject) is returned so the authorization-server can complete login.
     */
    @Transactional
    public AssertVerifyResponse verifyAssertion(String challengeId, String credentialIdB64,
                                                String authenticatorDataB64, String clientDataJsonB64,
                                                String signatureB64, String userHandleB64) {
        UUID challengePk;
        try {
            challengePk = UUID.fromString(challengeId);
        } catch (RuntimeException ex) {
            return failed();
        }

        Optional<WebAuthnChallenge> challengeOpt = challenges.findById(challengePk);
        if (challengeOpt.isEmpty()) {
            return failed();
        }
        WebAuthnChallenge stored = challengeOpt.get();
        if (stored.getType() != WebAuthnChallenge.Type.ASSERTION || stored.isExpired(Instant.now())) {
            challenges.delete(stored);
            return failed();
        }

        Optional<WebAuthnCredential> credOpt = credentials.findByCredentialId(credentialIdB64);
        if (credOpt.isEmpty()) {
            challenges.delete(stored);
            audit.record(stored.getTenantId(), null, WebAuthnAuditEvent.PASSKEY_ASSERT_FAILED,
                    credentialIdB64, null, "unknown credential");
            return failed();
        }
        WebAuthnCredential cred = credOpt.get();

        try {
            byte[] credentialId = B64URL_DEC.decode(credentialIdB64);
            byte[] userHandle = (userHandleB64 == null || userHandleB64.isBlank())
                    ? null : B64URL_DEC.decode(userHandleB64);
            byte[] authenticatorData = B64URL_DEC.decode(authenticatorDataB64);
            byte[] clientDataJson = B64URL_DEC.decode(clientDataJsonB64);
            byte[] signature = B64URL_DEC.decode(signatureB64);

            AuthenticationRequest request = new AuthenticationRequest(
                    credentialId, userHandle, authenticatorData, clientDataJson, signature);
            AuthenticationData authenticationData = webAuthnManager.parse(request);

            AttestedCredentialData acd = new AttestedCredentialDataConverter(objectConverter)
                    .convert(cred.getPublicKeyCose());
            // Reconstruct the stored credential. Only the counter + attested credential data (the public
            // key) matter for assertion verification; attestation/uv/backup/extensions/clientData are not
            // required and are supplied as null (non-strict manager, as at registration).
            CredentialRecord credentialRecord = new CredentialRecordImpl(
                    null,               // attestationStatement
                    null,               // uvInitialized
                    null,               // backupEligible
                    null,               // backupState
                    cred.getSignCount(),// counter
                    acd,                // attested credential data (holds the COSE public key)
                    null,               // authenticator extensions
                    null,               // collected client data
                    null,               // client extensions
                    null);              // transports

            Challenge challenge = new DefaultChallenge(B64URL_DEC.decode(stored.getChallenge()));
            // Verify against the RP the credential was registered under — the credential's OWNING tenant's
            // config, not the global props. `effectiveRp` returns global defaults for a tenant without a
            // custom row, so a hosted-flow passkey (registered under `localhost`) still verifies; a
            // tenant-app passkey registered under the tenant's own rpId now verifies correctly.
            EffectiveRp rp = effectiveRp(cred.getTenantId());
            ServerProperty serverProperty = new ServerProperty(rp.origins(), rp.rpId(), challenge, null);
            // M-svc-1: honour the tenant's configured userVerification policy instead of forcing "presence
            // only" — a tenant that requires UV gets it enforced by webauthn4j.
            boolean userVerificationRequired = "required".equals(rp.userVerification());
            AuthenticationParameters params = new AuthenticationParameters(
                    serverProperty,
                    credentialRecord,
                    null,                       // allowCredentials (usernameless)
                    userVerificationRequired,
                    true);                      // userPresenceRequired

            AuthenticationData verified = webAuthnManager.verify(authenticationData, params);

            // M-svc-1: reject a non-increasing signature counter (clone / replay detection) instead of
            // unconditionally overwriting it. A stored+new pair of 0/0 is allowed — some authenticators
            // never implement a counter — but any regression (new <= stored, when not that 0/0 case) fails.
            long storedCount = cred.getSignCount();
            long newCount = verified.getAuthenticatorData().getSignCount();
            if (newCount <= storedCount && !(newCount == 0 && storedCount == 0)) {
                challenges.delete(stored);
                audit.record(cred.getTenantId(), cred.getSubject(), WebAuthnAuditEvent.PASSKEY_ASSERT_FAILED,
                        cred.getCredentialId(), cred.getAaguid(),
                        "signature counter regression (stored=" + storedCount + ", presented=" + newCount + ")");
                return failed();
            }
            cred.setSignCount(newCount);
            cred.setLastUsedAt(Instant.now());
            credentials.save(cred);
            challenges.delete(stored);
            audit.record(cred.getTenantId(), cred.getSubject(), WebAuthnAuditEvent.PASSKEY_AUTHENTICATED,
                    cred.getCredentialId(), cred.getAaguid(), null);
            return new AssertVerifyResponse(true, cred.getTenantId(), cred.getSubject());
        } catch (RuntimeException ex) {
            // Do not leak the reason; a failed assertion is a `valid:false`, not an error. The challenge
            // is consumed so it cannot be replayed.
            challenges.delete(stored);
            audit.record(stored.getTenantId(), null, WebAuthnAuditEvent.PASSKEY_ASSERT_FAILED,
                    credentialIdB64, null, "assertion verification failed");
            return failed();
        }
    }

    private static AssertVerifyResponse failed() {
        return new AssertVerifyResponse(false, null, null);
    }

    public List<WebAuthnCredential> list(String tenantId, String subject) {
        return credentials.findByTenantIdAndSubjectOrderByCreatedAtDesc(tenantId, subject);
    }

    public boolean isEnrolled(String tenantId, String subject) {
        return credentials.existsByTenantIdAndSubject(tenantId, subject);
    }

    @Transactional
    public void remove(String tenantId, String subject, UUID id) {
        WebAuthnCredential cred = credentials.findByTenantIdAndSubjectAndId(tenantId, subject, id)
                .orElseThrow(() -> new MfaExceptions.NotFoundException("no such passkey"));
        String credentialId = cred.getCredentialId();
        String aaguid = cred.getAaguid();
        credentials.delete(cred);
        audit.record(tenantId, subject, WebAuthnAuditEvent.PASSKEY_REMOVED, credentialId, aaguid, null);
    }

    // --- Internal (server-to-server) tenant-app registration: uses the tenant's OWN RP config ---

    /**
     * Start a registration for a tenant-app (embedded) flow, driven by the authorization-server on behalf
     * of the tenant. Builds the options against the tenant's OWN {@link EffectiveRp} (rpId, rpName,
     * authenticator-selection from residentKey/userVerification/authenticatorAttachment, attestation).
     */
    @Transactional
    public Map<String, Object> startRegistrationForTenant(String tenantId, String subject,
                                                          String userName, String displayName) {
        return startRegistration(tenantId, subject, userName, displayName, effectiveRp(tenantId));
    }

    /**
     * Complete a tenant-app registration: verify the attestation against the tenant's OWN
     * {@link EffectiveRp} (rpId + origins) and persist the credential. A wrong/expired challenge surfaces
     * as a 400 via {@link MfaExceptions.InvalidVerificationException}.
     */
    @Transactional
    public WebAuthnCredential finishRegistrationForTenant(String tenantId, String subject,
                                                         String attestationObjectB64, String clientDataJsonB64,
                                                         String label) {
        return finishRegistration(tenantId, subject, attestationObjectB64, clientDataJsonB64,
                label, effectiveRp(tenantId));
    }

    private static Map<String, Object> descriptor(String credentialIdB64) {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("type", "public-key");
        d.put("id", credentialIdB64);
        return d;
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }
}
