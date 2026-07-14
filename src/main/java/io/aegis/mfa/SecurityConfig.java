package io.aegis.mfa;

import io.aegis.commons.security.SecurityHardening;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Resource-server security baseline (default-deny, shared hardening headers, 401-not-302).
 *
 * <p>Authorization model:
 * <ul>
 *   <li><b>Self-service</b> ({@code /api/v1/mfa/factors}, {@code /totp/**}, {@code /webauthn/**}) — any
 *       authenticated token. These endpoints operate <em>only</em> on the caller's own tenant+subject
 *       (both taken from the token, never the request body), so a valid session is sufficient and no
 *       extra scope is required. A user managing their own factors cannot touch anyone else's.</li>
 *   <li><b>Step-up</b> ({@code /internal/**}) — {@code SCOPE_mfa:verify}. Server-to-server only: the
 *       authorization-server calls these during login to check enrolment and validate a factor. Only
 *       the AS's own service token carries this scope.</li>
 *   <li><b>Admin</b> ({@code /admin/**}) — {@code SCOPE_mfa:admin}. Tenant admin resetting a user's MFA.</li>
 * </ul>
 */
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        SecurityHardening.applyHardeningHeaders(http);
        SecurityHardening.statelessBearerApi(http);
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        // Server-to-server step-up (authorization-server during login).
                        .requestMatchers("/api/v1/mfa/internal/**").hasAuthority("SCOPE_mfa:verify")
                        // Tenant-admin MFA reset.
                        .requestMatchers("/api/v1/mfa/admin/**").hasAuthority("SCOPE_mfa:admin")
                        // Tenant-admin WebAuthn RP config + passkey audit (tenant taken from the token).
                        .requestMatchers("/api/v1/mfa/webauthn/config").hasAuthority("SCOPE_tenant:admin")
                        .requestMatchers("/api/v1/mfa/webauthn/audit").hasAuthority("SCOPE_tenant:admin")
                        // Self-service factor management — any authenticated caller, own subject only.
                        .requestMatchers("/api/v1/mfa/**").authenticated()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }
}
