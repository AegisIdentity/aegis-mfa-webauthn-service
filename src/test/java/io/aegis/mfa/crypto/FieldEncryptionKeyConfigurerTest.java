package io.aegis.mfa.crypto;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

/**
 * Fail-open regression guard: the built-in dev field-encryption key must be used ONLY under the
 * explicit {@code dev} profile. With no profile (or any non-dev profile) and no configured key, startup
 * must fail fast rather than silently encrypting TOTP secrets with the public, source-controlled key.
 */
class FieldEncryptionKeyConfigurerTest {

    @Test
    void no_profile_and_no_key_fails_fast_instead_of_using_the_public_dev_key() {
        MockEnvironment env = new MockEnvironment(); // no active profiles
        assertThatThrownBy(() -> new FieldEncryptionKeyConfigurer(env, ""))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("aegis.crypto.field-key");
    }

    @Test
    void non_dev_profile_and_no_key_fails_fast() {
        MockEnvironment env = new MockEnvironment().withProperty("unused", "x");
        env.setActiveProfiles("test");
        assertThatThrownBy(() -> new FieldEncryptionKeyConfigurer(env, "  "))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void explicit_dev_profile_allows_the_built_in_dev_key() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("dev");
        assertThatCode(() -> new FieldEncryptionKeyConfigurer(env, "")).doesNotThrowAnyException();
    }

    @Test
    void a_configured_key_is_accepted_without_any_profile() {
        MockEnvironment env = new MockEnvironment();
        assertThatCode(() -> new FieldEncryptionKeyConfigurer(
                env, "YWVnaXMtZGV2LWZpZWxkLWVuY3J5cHRpb24ta2V5MzI=")).doesNotThrowAnyException();
    }
}
