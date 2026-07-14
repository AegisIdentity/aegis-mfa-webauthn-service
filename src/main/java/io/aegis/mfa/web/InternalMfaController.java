package io.aegis.mfa.web;

import io.aegis.mfa.domain.WebAuthnCredential;
import io.aegis.mfa.service.TotpService;
import io.aegis.mfa.service.TotpService.Enrollment;
import io.aegis.mfa.service.WebAuthnService;
import io.aegis.mfa.web.MfaDtos.AssertOptionsRequest;
import io.aegis.mfa.web.MfaDtos.AssertOptionsResponse;
import io.aegis.mfa.web.MfaDtos.AssertVerifyRequest;
import io.aegis.mfa.web.MfaDtos.AssertVerifyResponse;
import io.aegis.mfa.web.MfaDtos.InternalEnrollRequest;
import io.aegis.mfa.web.MfaDtos.InternalRegisterFinishRequest;
import io.aegis.mfa.web.MfaDtos.InternalRegisterFinishResponse;
import io.aegis.mfa.web.MfaDtos.InternalRegisterOptionsRequest;
import io.aegis.mfa.web.MfaDtos.StepUpStatus;
import io.aegis.mfa.web.MfaDtos.TotpEnrollResponse;
import io.aegis.mfa.web.MfaDtos.TotpValidateRequest;
import io.aegis.mfa.web.MfaDtos.ValidateResponse;
import jakarta.validation.Valid;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Server-to-server step-up MFA, consumed by the authorization-server during login. Gated by
 * {@code SCOPE_mfa:verify} (only the AS's own service token carries it). Unlike the self-service API,
 * these operate on a (tenant, subject) supplied by the caller — the AS is acting <em>on behalf of</em>
 * the user it is authenticating, having already verified the first factor (password).
 */
@RestController
@RequestMapping("/api/v1/mfa/internal")
public class InternalMfaController {

    private final TotpService totp;
    private final WebAuthnService webauthn;

    public InternalMfaController(TotpService totp, WebAuthnService webauthn) {
        this.totp = totp;
        this.webauthn = webauthn;
    }

    /** Which second factors a user has, so the AS knows whether (and how) to challenge. */
    @GetMapping("/status")
    public StepUpStatus status(@RequestParam String tenant, @RequestParam String subject) {
        List<String> methods = new ArrayList<>();
        if (totp.isEnabled(tenant, subject)) {
            methods.add("totp");
        }
        if (webauthn.isEnrolled(tenant, subject)) {
            methods.add("webauthn");
        }
        return new StepUpStatus(!methods.isEmpty(), methods);
    }

    /** Validate a TOTP code entered at the step-up prompt. */
    @PostMapping("/totp/validate")
    public ValidateResponse validateTotp(@Valid @RequestBody TotpValidateRequest request) {
        boolean valid = totp.validate(request.tenant(), request.subject(), request.code());
        return new ValidateResponse(valid);
    }

    /**
     * Force-enrol: mint (or rotate) a <em>disabled</em> TOTP secret for a user the AS is enrolling
     * mid-login. Confirm-before-activate — the secret is not a factor until {@link #verifyEnableTotp}
     * confirms a live code.
     */
    @PostMapping("/totp/enroll")
    public TotpEnrollResponse enrollTotp(@Valid @RequestBody InternalEnrollRequest request) {
        Enrollment e = totp.enroll(request.tenant(), request.subject(), request.account());
        return new TotpEnrollResponse(e.secret(), e.otpauthUri());
    }

    /**
     * Confirm a force-enrolment by verifying the first live code, which activates the factor. A wrong
     * code surfaces as 400 (no enrolment in progress → 404) via {@code MfaExceptionHandler}.
     */
    @PostMapping("/totp/verify-enable")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void verifyEnableTotp(@Valid @RequestBody TotpValidateRequest request) {
        totp.verifyAndEnable(request.tenant(), request.subject(), request.code());
    }

    /**
     * Begin a passwordless passkey login: mint a one-time assertion challenge (usernameless — we do not
     * yet know the user). The AS relays the returned options to the browser's
     * {@code navigator.credentials.get}.
     */
    @PostMapping("/webauthn/assert/options")
    public AssertOptionsResponse assertOptions(@RequestBody(required = false) AssertOptionsRequest request) {
        String tenant = request == null ? null : request.tenant();
        return webauthn.startAssertion(tenant);
    }

    /**
     * Complete a passwordless passkey login: verify the assertion. Any verification failure surfaces as
     * {@code valid:false} (never a 500) so login can fall through cleanly; on success the resolved
     * (tenant, subject) is returned for the AS to complete the login.
     */
    @PostMapping("/webauthn/assert/verify")
    public AssertVerifyResponse assertVerify(@Valid @RequestBody AssertVerifyRequest request) {
        return webauthn.verifyAssertion(request.challengeId(), request.credentialId(),
                request.authenticatorData(), request.clientDataJSON(),
                request.signature(), request.userHandle());
    }

    /**
     * Begin a tenant-app passkey registration on a user's behalf: mint + persist a one-time challenge and
     * return PublicKeyCredentialCreationOptions built against the tenant's OWN RP config (rpId/rpName +
     * authenticator-selection policy). The AS relays these to the browser's {@code navigator.credentials.create}.
     */
    @PostMapping("/webauthn/register/options")
    public Map<String, Object> registerOptions(@Valid @RequestBody InternalRegisterOptionsRequest request) {
        return webauthn.startRegistrationForTenant(request.tenant(), request.subject(),
                request.userName(), request.displayName());
    }

    /**
     * Complete a tenant-app passkey registration: verify the attestation against the tenant's OWN rpId +
     * origins and store the credential. A wrong/expired challenge surfaces as 400 via
     * {@code MfaExceptionHandler}. Returns the stored passkey's id, label, and credentialId.
     */
    @PostMapping("/webauthn/register/finish")
    @ResponseStatus(HttpStatus.CREATED)
    public InternalRegisterFinishResponse registerFinish(@Valid @RequestBody InternalRegisterFinishRequest request) {
        WebAuthnCredential saved = webauthn.finishRegistrationForTenant(request.tenant(), request.subject(),
                request.attestationObject(), request.clientDataJSON(), request.label());
        return new InternalRegisterFinishResponse(
                saved.getId().toString(), saved.getLabel(), saved.getCredentialId());
    }
}
