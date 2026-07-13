package io.aegis.mfa;

import io.aegis.commons.security.SecurityHardening;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/** Resource-server security baseline (default-deny, shared hardening headers, 401-not-302).
 * Endpoint-specific scopes are added as real endpoints are implemented. */
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        SecurityHardening.applyHardeningHeaders(http);
        SecurityHardening.statelessBearerApi(http);
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        .requestMatchers("/api/**").hasAuthority("SCOPE_mfa:admin")
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }
}
