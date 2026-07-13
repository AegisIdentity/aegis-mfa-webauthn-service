package io.aegis.mfa.service;

import io.aegis.mfa.config.MfaProperties;
import io.aegis.mfa.domain.TotpCredential;
import io.aegis.mfa.domain.TotpCredentialRepository;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * TOTP (authenticator-app) enrolment and verification, tenant + subject scoped.
 *
 * <p>Confirm-before-activate: {@link #enroll} mints a fresh secret and stores it <em>disabled</em>;
 * only {@link #verifyAndEnable} (the user typing a live code) flips it on. So an abandoned enrolment
 * never becomes a factor that can lock a user out, and re-enrolling simply rotates the secret.
 */
@Service
public class TotpService {

    private final TotpCredentialRepository repository;
    private final MfaProperties props;

    public TotpService(TotpCredentialRepository repository, MfaProperties props) {
        this.repository = repository;
        this.props = props;
    }

    /** A TOTP enrolment challenge: the secret to store in the app plus the otpauth URI to render as a QR. */
    public record Enrollment(String secret, String otpauthUri) {
    }

    @Transactional
    public Enrollment enroll(String tenantId, String subject, String accountName) {
        String secret = TotpGenerator.randomSecretBase32();
        TotpCredential existing = repository.findByTenantIdAndSubject(tenantId, subject).orElse(null);
        if (existing == null) {
            repository.save(new TotpCredential(tenantId, subject, secret));
        } else {
            // Re-enrolment rotates the secret and drops back to unverified until confirmed.
            existing.setSecretBase32(secret);
            existing.setEnabled(false);
            repository.save(existing);
        }
        return new Enrollment(secret, otpauthUri(accountName, secret));
    }

    @Transactional
    public void verifyAndEnable(String tenantId, String subject, String code) {
        TotpCredential cred = repository.findByTenantIdAndSubject(tenantId, subject)
                .orElseThrow(() -> new MfaExceptions.NotFoundException("no TOTP enrolment in progress"));
        if (!codeMatches(cred, code)) {
            throw new MfaExceptions.InvalidVerificationException("code did not match");
        }
        cred.setEnabled(true);
        cred.setLastUsedAt(Instant.now());
        repository.save(cred);
    }

    /** Step-up validation of an already-enabled TOTP. Returns false rather than throwing so the caller
     *  (login flow) can re-prompt without a 4xx. Updates last-used on success. */
    @Transactional
    public boolean validate(String tenantId, String subject, String code) {
        TotpCredential cred = repository.findByTenantIdAndSubject(tenantId, subject).orElse(null);
        if (cred == null || !cred.isEnabled() || !codeMatches(cred, code)) {
            return false;
        }
        cred.setLastUsedAt(Instant.now());
        repository.save(cred);
        return true;
    }

    public boolean isEnabled(String tenantId, String subject) {
        return repository.findByTenantIdAndSubject(tenantId, subject)
                .map(TotpCredential::isEnabled).orElse(false);
    }

    public TotpCredential find(String tenantId, String subject) {
        return repository.findByTenantIdAndSubject(tenantId, subject).orElse(null);
    }

    @Transactional
    public void remove(String tenantId, String subject) {
        repository.deleteByTenantIdAndSubject(tenantId, subject);
    }

    private boolean codeMatches(TotpCredential cred, String code) {
        MfaProperties.Totp t = props.getTotp();
        return TotpGenerator.verify(cred.getSecretBase32(), code, System.currentTimeMillis(),
                t.getDigits(), t.getPeriodSeconds(), t.getAllowedSkewSteps());
    }

    private String otpauthUri(String accountName, String secret) {
        MfaProperties.Totp t = props.getTotp();
        String issuer = t.getIssuer();
        String label = enc(issuer) + ":" + enc(accountName);
        return "otpauth://totp/" + label
                + "?secret=" + secret
                + "&issuer=" + enc(issuer)
                + "&algorithm=SHA1"
                + "&digits=" + t.getDigits()
                + "&period=" + t.getPeriodSeconds();
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
