package io.aegis.mfa.service;

/** Domain exceptions, mapped to HTTP status codes by {@code MfaExceptionHandler}. */
public final class MfaExceptions {

    private MfaExceptions() {
    }

    /** No such enrolment / ceremony state to act on (→ 404). */
    public static class NotFoundException extends RuntimeException {
        public NotFoundException(String message) {
            super(message);
        }
    }

    /** A submitted code/assertion/ceremony was invalid or expired (→ 400). */
    public static class InvalidVerificationException extends RuntimeException {
        public InvalidVerificationException(String message) {
            super(message);
        }
    }
}
