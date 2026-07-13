package io.aegis.mfa.web;

import io.aegis.mfa.service.TotpService;
import io.aegis.mfa.service.WebAuthnService;
import io.aegis.mfa.web.MfaDtos.StepUpStatus;
import io.aegis.mfa.web.MfaDtos.TotpValidateRequest;
import io.aegis.mfa.web.MfaDtos.ValidateResponse;
import jakarta.validation.Valid;
import java.util.ArrayList;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
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
}
