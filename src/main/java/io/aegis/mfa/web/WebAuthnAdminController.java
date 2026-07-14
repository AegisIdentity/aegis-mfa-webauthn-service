package io.aegis.mfa.web;

import io.aegis.mfa.service.WebAuthnAuditService;
import io.aegis.mfa.service.WebAuthnConfigService;
import io.aegis.mfa.web.MfaDtos.WebAuthnAuditView;
import io.aegis.mfa.web.MfaDtos.WebAuthnConfigUpdate;
import io.aegis.mfa.web.MfaDtos.WebAuthnConfigView;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Tenant-admin surface for passkey/WebAuthn: the per-tenant RP configuration (for the tenant's OWN app,
 * Model B) and the passkey audit trail. Gated by {@code SCOPE_tenant:admin}; the tenant is always taken
 * from the caller's token, never the request, so an admin only ever manages their own organization.
 *
 * <p>The config here is a setup surface only — it is <em>not</em> wired into the Aegis-hosted
 * registration/assertion ceremony, which keeps using the global config. It is consumed by
 * tenant-app-facing endpoints (future runtime).
 */
@RestController
public class WebAuthnAdminController {

    private final WebAuthnConfigService config;
    private final WebAuthnAuditService audit;

    public WebAuthnAdminController(WebAuthnConfigService config, WebAuthnAuditService audit) {
        this.config = config;
        this.audit = audit;
    }

    @GetMapping("/api/v1/mfa/webauthn/config")
    public WebAuthnConfigView getConfig(@AuthenticationPrincipal Jwt caller) {
        return WebAuthnConfigView.of(config.effective(tenantOf(caller)));
    }

    @PutMapping("/api/v1/mfa/webauthn/config")
    public WebAuthnConfigView updateConfig(@AuthenticationPrincipal Jwt caller,
                                           @Valid @RequestBody WebAuthnConfigUpdate body) {
        boolean enabled = body.enabled() == null || body.enabled();
        return WebAuthnConfigView.of(config.update(tenantOf(caller),
                body.rpId(), body.rpName(), body.origins(),
                body.userVerification(), body.authenticatorAttachment(),
                body.residentKey(), body.attestation(), enabled));
    }

    @GetMapping("/api/v1/mfa/webauthn/audit")
    public List<WebAuthnAuditView> audit(@AuthenticationPrincipal Jwt caller,
                                         @RequestParam(required = false) Integer limit) {
        return audit.recent(tenantOf(caller), limit).stream().map(WebAuthnAuditView::of).toList();
    }

    private static String tenantOf(Jwt caller) {
        String tenant = caller.getClaimAsString("tenant");
        if (tenant == null || tenant.isBlank()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "token carries no tenant");
        }
        return tenant;
    }
}
