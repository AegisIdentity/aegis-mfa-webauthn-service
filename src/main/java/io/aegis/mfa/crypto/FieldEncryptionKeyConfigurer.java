package io.aegis.mfa.crypto;

import java.util.Arrays;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Installs the AES-256 field-encryption key at startup (H5). The key is a base64-encoded 32-byte value
 * from {@code aegis.crypto.field-key} (env {@code AEGIS_FIELD_ENC_KEY}).
 *
 * <p>A real key from {@code aegis.crypto.field-key} is <strong>required</strong> in every deployment —
 * startup fails fast if it is absent or blank. The only exception is when the Spring {@code dev} profile
 * is <strong>explicitly</strong> active: then a fixed, well-known dev key is used so the service runs
 * out-of-the-box. That dev key is NOT a secret and must never protect real data. This is a fail-closed,
 * opt-in design — a deploy that forgets to set the profile/key fails to start rather than silently
 * encrypting with the public, source-controlled key.
 */
@Component
public class FieldEncryptionKeyConfigurer {

    private static final Logger log = LoggerFactory.getLogger(FieldEncryptionKeyConfigurer.class);

    /** Fixed dev key (32 bytes, base64). Used ONLY under the explicit {@code dev} profile — never protects real data. */
    private static final String DEV_KEY_B64 = "YWVnaXMtZGV2LWZpZWxkLWVuY3J5cHRpb24ta2V5MzI=";

    public FieldEncryptionKeyConfigurer(Environment env,
                                        @Value("${aegis.crypto.field-key:}") String configuredKey) {
        byte[] keyBytes;
        if (StringUtils.hasText(configuredKey)) {
            keyBytes = Base64.getDecoder().decode(configuredKey.trim());
        } else if (SecretsPolicy.devProfileActive(env)) {
            log.warn("Using the built-in DEV field-encryption key — TOTP secrets are NOT protected by a "
                    + "real secret. This is only allowed under the explicit 'dev' profile.");
            keyBytes = Base64.getDecoder().decode(DEV_KEY_B64);
        } else {
            throw new IllegalStateException(
                    "aegis.crypto.field-key (AEGIS_FIELD_ENC_KEY) must be set — TOTP secrets are encrypted "
                            + "at rest (H5). Refusing to start with the built-in dev key outside the explicit "
                            + "'dev' profile (activate the 'dev' Spring profile to use the dev key locally).");
        }
        FieldEncryption.setKey(keyBytes);
        Arrays.fill(keyBytes, (byte) 0);
    }
}
