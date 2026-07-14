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
import io.aegis.mfa.domain.WebAuthnChallenge;
import io.aegis.mfa.domain.WebAuthnChallengeRepository;
import io.aegis.mfa.domain.WebAuthnCredential;
import io.aegis.mfa.domain.WebAuthnCredentialRepository;
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
    private final WebAuthnManager webAuthnManager;
    private final ObjectConverter objectConverter;

    public WebAuthnService(WebAuthnCredentialRepository credentials,
                           WebAuthnChallengeRepository challenges,
                           MfaProperties props) {
        this.credentials = credentials;
        this.challenges = challenges;
        this.props = props;
        this.objectConverter = new ObjectConverter();
        // Non-strict: do not require an attestation trust-anchor chain (passkeys use `none`).
        this.webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);
    }

    /**
     * Start a registration ceremony: mint + persist a one-time challenge and return
     * PublicKeyCredentialCreationOptions (as a plain JSON-friendly map the browser passes to
     * {@code navigator.credentials.create}).
     */
    @Transactional
    public Map<String, Object> startRegistration(String tenantId, String subject, String userName, String displayName) {
        byte[] challengeBytes = randomBytes(32);
        String challengeB64 = B64URL.encodeToString(challengeBytes);
        challenges.deleteByTenantIdAndSubjectAndType(tenantId, subject, WebAuthnChallenge.Type.REGISTRATION);
        challenges.save(new WebAuthnChallenge(tenantId, subject, challengeB64,
                WebAuthnChallenge.Type.REGISTRATION,
                Instant.now().plusSeconds(props.getWebauthn().getChallengeTtlSeconds())));

        MfaProperties.WebAuthn cfg = props.getWebauthn();
        // User handle: a stable per-user id (the subject) — never PII, so it is safe on the authenticator.
        String userHandle = B64URL.encodeToString(subject.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        List<Map<String, Object>> exclude = credentials
                .findByTenantIdAndSubjectOrderByCreatedAtDesc(tenantId, subject).stream()
                .map(c -> descriptor(c.getCredentialId()))
                .collect(Collectors.toList());

        Map<String, Object> options = new LinkedHashMap<>();
        options.put("challenge", challengeB64);
        options.put("rp", Map.of("id", cfg.getRpId(), "name", cfg.getRpName()));
        options.put("user", Map.of("id", userHandle, "name", userName, "displayName", displayName));
        options.put("pubKeyCredParams", List.of(
                Map.of("type", "public-key", "alg", -7),    // ES256
                Map.of("type", "public-key", "alg", -257))); // RS256
        options.put("timeout", props.getWebauthn().getChallengeTtlSeconds() * 1000);
        options.put("attestation", "none");
        options.put("authenticatorSelection", Map.of(
                "residentKey", "preferred", "userVerification", "preferred"));
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
        ServerProperty serverProperty = new ServerProperty(origins(), props.getWebauthn().getRpId(), challenge, null);

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
        byte[] challengeBytes = randomBytes(32);
        String challengeB64 = B64URL.encodeToString(challengeBytes);
        WebAuthnChallenge saved = challenges.save(new WebAuthnChallenge(
                tenantId, "*", challengeB64, WebAuthnChallenge.Type.ASSERTION,
                Instant.now().plusSeconds(props.getWebauthn().getChallengeTtlSeconds())));
        return new AssertOptionsResponse(
                saved.getId().toString(),
                challengeB64,
                props.getWebauthn().getRpId(),
                props.getWebauthn().getChallengeTtlSeconds() * 1000,
                "preferred",
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
            ServerProperty serverProperty = new ServerProperty(origins(), props.getWebauthn().getRpId(), challenge, null);
            AuthenticationParameters params = new AuthenticationParameters(
                    serverProperty,
                    credentialRecord,
                    null,   // allowCredentials (usernameless)
                    false,  // userVerificationRequired
                    true);  // userPresenceRequired

            AuthenticationData verified = webAuthnManager.verify(authenticationData, params);

            long newCount = verified.getAuthenticatorData().getSignCount();
            cred.setSignCount(newCount);
            cred.setLastUsedAt(Instant.now());
            credentials.save(cred);
            challenges.delete(stored);
            return new AssertVerifyResponse(true, cred.getTenantId(), cred.getSubject());
        } catch (RuntimeException ex) {
            // Do not leak the reason; a failed assertion is a `valid:false`, not an error. The challenge
            // is consumed so it cannot be replayed.
            challenges.delete(stored);
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
        credentials.delete(cred);
    }

    private Set<Origin> origins() {
        return props.getWebauthn().getAllowedOrigins().stream()
                .map(Origin::new)
                .collect(Collectors.toSet());
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
