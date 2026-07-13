package io.aegis.mfa.service;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
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
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
