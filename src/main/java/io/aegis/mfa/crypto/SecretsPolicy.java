package io.aegis.mfa.crypto;

import java.util.Arrays;
import org.springframework.core.env.Environment;

/**
 * Decides whether externally-supplied secrets (encryption keys, DB/client passwords) are mandatory.
 * True in a {@code prod}/{@code stage} deployment, or whenever {@code aegis.security.require-external-secrets=true}
 * is set explicitly. False for local dev and tests (no active profile), where built-in dev defaults apply.
 */
public final class SecretsPolicy {

    private SecretsPolicy() {
    }

    public static boolean externalSecretsRequired(Environment env) {
        boolean prodLike = Arrays.stream(env.getActiveProfiles())
                .anyMatch(p -> p.equalsIgnoreCase("prod")
                        || p.equalsIgnoreCase("production")
                        || p.equalsIgnoreCase("stage")
                        || p.equalsIgnoreCase("staging"));
        return prodLike || env.getProperty("aegis.security.require-external-secrets", Boolean.class, false);
    }

    /**
     * True only when the Spring {@code dev} profile is explicitly active. Mirrors {@code @Profile("dev")}
     * semantics (see {@code getActiveProfiles}) so built-in dev defaults (e.g. the well-known dev
     * field-encryption key) are opt-in — used only when someone deliberately runs with {@code dev}, never
     * as a silent fallback when no profile is set.
     */
    public static boolean devProfileActive(Environment env) {
        return Arrays.stream(env.getActiveProfiles()).anyMatch(p -> p.equalsIgnoreCase("dev"));
    }
}
