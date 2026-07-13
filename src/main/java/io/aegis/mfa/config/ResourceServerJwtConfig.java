package io.aegis.mfa.config;

import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * Resource-server JWT decoder that survives the Dockerized split-horizon issuer problem: keys are
 * fetched from a reachable in-network JWKS URI and the issuer is validated against an allowlist
 * (browser-facing + in-network), rather than a single {@code issuer-uri} that only one caller can
 * satisfy. Signature and expiry are still enforced. See {@code aegis-identity-service}'s copy for the
 * full rationale (this should eventually move to aegis-platform-commons).
 */
@Configuration(proxyBeanMethods = false)
public class ResourceServerJwtConfig {

    @Bean
    public JwtDecoder jwtDecoder(
            @Value("${aegis.jwt.jwk-set-uri:http://localhost:9000/oauth2/jwks}") String jwkSetUri,
            @Value("${aegis.jwt.accepted-issuers:http://localhost:9000,http://authorization-server:9000}")
            List<String> acceptedIssuers) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(),
                issuerAllowlistValidator(List.copyOf(acceptedIssuers))));
        return decoder;
    }

    private static OAuth2TokenValidator<Jwt> issuerAllowlistValidator(List<String> acceptedIssuers) {
        return jwt -> {
            String iss = jwt.getIssuer() == null ? null : jwt.getIssuer().toString();
            boolean ok = iss != null && acceptedIssuers.stream()
                    .anyMatch(base -> iss.equals(base) || iss.startsWith(base + "/"));
            return ok ? OAuth2TokenValidatorResult.success()
                    : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token",
                            "issuer not accepted: " + iss, null));
        };
    }
}
