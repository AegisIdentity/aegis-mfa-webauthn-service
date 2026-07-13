package io.aegis.mfa.service;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * RFC 6238 TOTP over RFC 4226 HOTP (HMAC-SHA1), plus RFC 4648 Base32 for the authenticator-app secret
 * format. Deliberately dependency-free and pure so it can be unit-tested against the RFC 6238 Appendix
 * B reference vectors — the strongest possible evidence the one-time-code math is correct.
 *
 * <p>Verification is constant-time and checks a small window of steps around "now" to tolerate clock
 * skew between the server and the user's phone.
 */
public final class TotpGenerator {

    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final SecureRandom RANDOM = new SecureRandom();

    private TotpGenerator() {
    }

    /** A new random Base32 secret. 20 bytes = 160 bits, the SHA-1 block-friendly size RFC 4226 assumes. */
    public static String randomSecretBase32() {
        byte[] buf = new byte[20];
        RANDOM.nextBytes(buf);
        return base32Encode(buf);
    }

    /** The TOTP code for the given secret at the given instant, zero-padded to {@code digits}. */
    public static String code(String secretBase32, long timeMillis, int digits, int periodSeconds) {
        long counter = Math.floorDiv(timeMillis / 1000L, (long) periodSeconds);
        return hotp(base32Decode(secretBase32), counter, digits);
    }

    /**
     * True if {@code candidate} matches the code for {@code secret} at {@code timeMillis}, allowing
     * {@code skewSteps} periods on either side. Uses a length-safe constant-time comparison.
     */
    public static boolean verify(String secretBase32, String candidate, long timeMillis,
                                 int digits, int periodSeconds, int skewSteps) {
        if (candidate == null) {
            return false;
        }
        String trimmed = candidate.trim();
        if (trimmed.length() != digits) {
            return false;
        }
        byte[] key = base32Decode(secretBase32);
        long counter = Math.floorDiv(timeMillis / 1000L, (long) periodSeconds);
        for (long i = -skewSteps; i <= skewSteps; i++) {
            String expected = hotp(key, counter + i, digits);
            if (constantTimeEquals(expected, trimmed)) {
                return true;
            }
        }
        return false;
    }

    private static String hotp(byte[] key, long counter, int digits) {
        byte[] msg = ByteBuffer.allocate(8).putLong(counter).array();
        byte[] hash = hmacSha1(key, msg);
        int offset = hash[hash.length - 1] & 0x0f;
        int binary = ((hash[offset] & 0x7f) << 24)
                | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8)
                | (hash[offset + 3] & 0xff);
        int otp = binary % (int) Math.pow(10, digits);
        return String.format("%0" + digits + "d", otp);
    }

    private static byte[] hmacSha1(byte[] key, byte[] message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            return mac.doFinal(message);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("HMAC-SHA1 unavailable", e);
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }

    static String base32Encode(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xff);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                int index = (buffer >> (bitsLeft - 5)) & 0x1f;
                bitsLeft -= 5;
                sb.append(BASE32_ALPHABET.charAt(index));
            }
        }
        if (bitsLeft > 0) {
            int index = (buffer << (5 - bitsLeft)) & 0x1f;
            sb.append(BASE32_ALPHABET.charAt(index));
        }
        return sb.toString();
    }

    static byte[] base32Decode(String encoded) {
        String clean = encoded.trim().replace("=", "").replace(" ", "").toUpperCase();
        int outLength = clean.length() * 5 / 8;
        byte[] result = new byte[outLength];
        int buffer = 0;
        int bitsLeft = 0;
        int index = 0;
        for (int i = 0; i < clean.length(); i++) {
            int val = BASE32_ALPHABET.indexOf(clean.charAt(i));
            if (val < 0) {
                throw new IllegalArgumentException("not a Base32 character: " + clean.charAt(i));
            }
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                result[index++] = (byte) ((buffer >> (bitsLeft - 8)) & 0xff);
                bitsLeft -= 8;
            }
        }
        return result;
    }
}
