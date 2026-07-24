package io.aegis.mfa.crypto;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-256-GCM authenticated encryption for sensitive column values (H5 — TOTP shared secrets at rest).
 *
 * <p>The 256-bit key is supplied once at startup by {@link FieldEncryptionKeyConfigurer} (sourced from a
 * secret manager / env var in non-dev). Ciphertext is stored as {@code v1:base64(iv||ciphertext||tag)}
 * with a fresh 96-bit random IV per value. A value that does <em>not</em> carry the {@code v1:} prefix is
 * treated as legacy plaintext and returned as-is on read, so pre-existing rows keep working — a one-off
 * backfill (re-save each row) migrates them to ciphertext. New writes are always encrypted.
 */
public final class FieldEncryption {

    /** Prefix marking a value as v1 AES-GCM ciphertext (distinguishes it from legacy plaintext). */
    static final String PREFIX = "v1:";
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    /** Set once at startup; {@code volatile} for safe publication to the Hibernate-created converter. */
    private static volatile SecretKeySpec key;

    private FieldEncryption() {
    }

    static void setKey(byte[] keyBytes) {
        if (keyBytes == null || keyBytes.length != 32) {
            throw new IllegalStateException("field encryption key must be 32 bytes (AES-256)");
        }
        key = new SecretKeySpec(keyBytes, "AES");
    }

    /** Encrypt a plaintext value to {@code v1:base64(iv||ct)}. Returns {@code null} for {@code null}. */
    public static String encrypt(String plaintext) {
        if (plaintext == null) {
            return null;
        }
        SecretKeySpec k = requireKey();
        try {
            byte[] iv = new byte[IV_BYTES];
            RANDOM.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, k, new GCMParameterSpec(TAG_BITS, iv));
            byte[] ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] out = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ct, 0, out, iv.length, ct.length);
            return PREFIX + Base64.getEncoder().encodeToString(out);
        } catch (Exception e) {
            throw new IllegalStateException("field encryption failed", e);
        }
    }

    /** Decrypt a stored value. A value without the {@code v1:} prefix is legacy plaintext, returned as-is. */
    public static String decrypt(String stored) {
        if (stored == null) {
            return null;
        }
        if (!stored.startsWith(PREFIX)) {
            return stored; // legacy plaintext row — see class Javadoc (backfill migrates these)
        }
        SecretKeySpec k = requireKey();
        try {
            byte[] blob = Base64.getDecoder().decode(stored.substring(PREFIX.length()));
            byte[] iv = new byte[IV_BYTES];
            System.arraycopy(blob, 0, iv, 0, IV_BYTES);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, k, new GCMParameterSpec(TAG_BITS, iv));
            byte[] pt = cipher.doFinal(blob, IV_BYTES, blob.length - IV_BYTES);
            return new String(pt, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("field decryption failed", e);
        }
    }

    private static SecretKeySpec requireKey() {
        SecretKeySpec k = key;
        if (k == null) {
            throw new IllegalStateException(
                    "field encryption key not configured (aegis.crypto.field-key / AEGIS_FIELD_ENC_KEY)");
        }
        return k;
    }
}
