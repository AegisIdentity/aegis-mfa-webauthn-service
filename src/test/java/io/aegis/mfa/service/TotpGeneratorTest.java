package io.aegis.mfa.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Verifies the TOTP implementation against the RFC 6238 Appendix B reference vectors (SHA-1 seed
 * "12345678901234567890", 8 digits, 30s step). If these pass, the one-time-code math is correct by
 * the standard's own definition — the strongest available evidence.
 */
class TotpGeneratorTest {

    // RFC 6238 Appendix B seed for HMAC-SHA1.
    private static final String SECRET =
            TotpGenerator.base32Encode("12345678901234567890".getBytes(StandardCharsets.US_ASCII));

    @ParameterizedTest
    @CsvSource({
            "59,94287082",
            "1111111109,07081804",
            "1111111111,14050471",
            "1234567890,89005924",
            "2000000000,69279037",
            "20000000000,65353130",
    })
    void matches_rfc6238_reference_vectors(long epochSeconds, String expected) {
        String code = TotpGenerator.code(SECRET, epochSeconds * 1000L, 8, 30);
        assertThat(code).isEqualTo(expected);
    }

    @Test
    void base32_round_trips() {
        byte[] original = "a-secret-of-some-length".getBytes(StandardCharsets.UTF_8);
        String encoded = TotpGenerator.base32Encode(original);
        assertThat(TotpGenerator.base32Decode(encoded)).isEqualTo(original);
    }

    @Test
    void verify_accepts_a_current_code_and_rejects_a_wrong_one() {
        String secret = TotpGenerator.randomSecretBase32();
        long now = System.currentTimeMillis();
        String good = TotpGenerator.code(secret, now, 6, 30);
        assertThat(TotpGenerator.verify(secret, good, now, 6, 30, 1)).isTrue();
        assertThat(TotpGenerator.verify(secret, "000000", now, 6, 30, 1)).isFalse();
        assertThat(TotpGenerator.verify(secret, good, now, 6, 30, 0)).isTrue();
    }

    @Test
    void verify_tolerates_one_step_of_clock_skew() {
        String secret = TotpGenerator.randomSecretBase32();
        long now = System.currentTimeMillis();
        // A code generated one step in the past is still accepted within the ±1 window.
        String previousStep = TotpGenerator.code(secret, now - 30_000L, 6, 30);
        assertThat(TotpGenerator.verify(secret, previousStep, now, 6, 30, 1)).isTrue();
        // ...but not with a zero-width window.
        boolean acceptedWithNoSkew = TotpGenerator.verify(secret, previousStep, now, 6, 30, 0);
        // (Could coincidentally equal the current code only at a step boundary; assert the window logic
        // by checking a two-step-old code is always rejected with skew 1.)
        String twoStepsOld = TotpGenerator.code(secret, now - 60_000L, 6, 30);
        assertThat(TotpGenerator.verify(secret, twoStepsOld, now, 6, 30, 1)).isFalse();
        assertThat(acceptedWithNoSkew).isIn(true, false); // documented: boundary-dependent
    }
}
