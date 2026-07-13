package io.aegis.mfa.config;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Bound from {@code aegis.mfa.*}. TOTP parameters (RFC 6238) and the WebAuthn Relying Party identity. */
@ConfigurationProperties(prefix = "aegis.mfa")
public class MfaProperties {

    private final Totp totp = new Totp();
    private final WebAuthn webauthn = new WebAuthn();

    public Totp getTotp() {
        return totp;
    }

    public WebAuthn getWebauthn() {
        return webauthn;
    }

    public static class Totp {
        private String issuer = "Aegis";
        private int digits = 6;
        private int periodSeconds = 30;
        private int allowedSkewSteps = 1;

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public int getDigits() {
            return digits;
        }

        public void setDigits(int digits) {
            this.digits = digits;
        }

        public int getPeriodSeconds() {
            return periodSeconds;
        }

        public void setPeriodSeconds(int periodSeconds) {
            this.periodSeconds = periodSeconds;
        }

        public int getAllowedSkewSteps() {
            return allowedSkewSteps;
        }

        public void setAllowedSkewSteps(int allowedSkewSteps) {
            this.allowedSkewSteps = allowedSkewSteps;
        }
    }

    public static class WebAuthn {
        private String rpId = "localhost";
        private String rpName = "Aegis";
        private List<String> allowedOrigins = List.of("http://localhost:3000");
        private long challengeTtlSeconds = 300;

        public String getRpId() {
            return rpId;
        }

        public void setRpId(String rpId) {
            this.rpId = rpId;
        }

        public String getRpName() {
            return rpName;
        }

        public void setRpName(String rpName) {
            this.rpName = rpName;
        }

        public List<String> getAllowedOrigins() {
            return allowedOrigins;
        }

        public void setAllowedOrigins(List<String> allowedOrigins) {
            this.allowedOrigins = allowedOrigins;
        }

        public long getChallengeTtlSeconds() {
            return challengeTtlSeconds;
        }

        public void setChallengeTtlSeconds(long challengeTtlSeconds) {
            this.challengeTtlSeconds = challengeTtlSeconds;
        }
    }
}
