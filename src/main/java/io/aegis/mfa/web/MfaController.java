package io.aegis.mfa.web;

import io.aegis.mfa.domain.WebAuthnCredential;
import io.aegis.mfa.service.TotpService;
import io.aegis.mfa.service.WebAuthnService;
import io.aegis.mfa.web.MfaDtos.CodeRequest;
import io.aegis.mfa.web.MfaDtos.FactorsResponse;
import io.aegis.mfa.web.MfaDtos.PasskeyFinishRequest;
import io.aegis.mfa.web.MfaDtos.PasskeyView;
import io.aegis.mfa.web.MfaDtos.TotpEnrollResponse;
import io.aegis.mfa.web.MfaDtos.TotpView;
import jakarta.validation.Valid;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Self-service MFA factor management for the end-user portal. Every operation is scoped to the caller's
 * own tenant + subject, both taken from the bearer token — never from the request — so a user can only
 * ever enrol or remove <em>their own</em> factors.
 */
@RestController
@RequestMapping("/api/v1/mfa")
public class MfaController {

    private final TotpService totp;
    private final WebAuthnService webauthn;

    public MfaController(TotpService totp, WebAuthnService webauthn) {
        this.totp = totp;
        this.webauthn = webauthn;
    }

    @GetMapping("/factors")
    public FactorsResponse factors(@AuthenticationPrincipal Jwt caller) {
        String tenant = tenantOf(caller);
        String subject = caller.getSubject();
        List<PasskeyView> passkeys = webauthn.list(tenant, subject).stream()
                .map(PasskeyView::of).toList();
        return new FactorsResponse(TotpView.of(totp.find(tenant, subject)), passkeys);
    }

    @PostMapping("/totp/enroll")
    public TotpEnrollResponse enrollTotp(@AuthenticationPrincipal Jwt caller) {
        String tenant = tenantOf(caller);
        var e = totp.enroll(tenant, caller.getSubject(), accountOf(caller));
        return new TotpEnrollResponse(e.secret(), e.otpauthUri());
    }

    @PostMapping("/totp/verify")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void verifyTotp(@AuthenticationPrincipal Jwt caller, @Valid @RequestBody CodeRequest request) {
        totp.verifyAndEnable(tenantOf(caller), caller.getSubject(), request.code());
    }

    @DeleteMapping("/totp")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void removeTotp(@AuthenticationPrincipal Jwt caller) {
        totp.remove(tenantOf(caller), caller.getSubject());
    }

    @PostMapping("/webauthn/register/options")
    public Map<String, Object> registrationOptions(@AuthenticationPrincipal Jwt caller) {
        return webauthn.startRegistration(tenantOf(caller), caller.getSubject(),
                accountOf(caller), displayNameOf(caller));
    }

    @PostMapping("/webauthn/register/finish")
    @ResponseStatus(HttpStatus.CREATED)
    public PasskeyView finishRegistration(@AuthenticationPrincipal Jwt caller,
                                          @Valid @RequestBody PasskeyFinishRequest request) {
        WebAuthnCredential saved = webauthn.finishRegistration(tenantOf(caller), caller.getSubject(),
                request.attestationObject(), request.clientDataJSON(), request.label());
        return PasskeyView.of(saved);
    }

    @DeleteMapping("/webauthn/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void removePasskey(@AuthenticationPrincipal Jwt caller, @PathVariable UUID id) {
        webauthn.remove(tenantOf(caller), caller.getSubject(), id);
    }

    private static String tenantOf(Jwt caller) {
        String tenant = caller.getClaimAsString("tenant");
        if (tenant == null || tenant.isBlank()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "token carries no tenant");
        }
        return tenant;
    }

    private static String accountOf(Jwt caller) {
        String u = caller.getClaimAsString("preferred_username");
        return (u == null || u.isBlank()) ? caller.getSubject() : u;
    }

    private static String displayNameOf(Jwt caller) {
        String name = caller.getClaimAsString("name");
        return (name == null || name.isBlank()) ? accountOf(caller) : name;
    }
}
