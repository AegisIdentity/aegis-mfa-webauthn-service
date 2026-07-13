package io.aegis.mfa.web;

import io.aegis.mfa.service.MfaExceptions;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Maps MFA domain failures to clean HTTP responses. Never leaks secrets, stack traces, or internals. */
@RestControllerAdvice
public class MfaExceptionHandler {

    @ExceptionHandler(MfaExceptions.NotFoundException.class)
    public ResponseEntity<Map<String, String>> notFound(MfaExceptions.NotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", ex.getMessage()));
    }

    @ExceptionHandler(MfaExceptions.InvalidVerificationException.class)
    public ResponseEntity<Map<String, String>> invalid(MfaExceptions.InvalidVerificationException ex) {
        return ResponseEntity.badRequest().body(Map.of("error", ex.getMessage()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> validation(MethodArgumentNotValidException ex) {
        String msg = ex.getBindingResult().getFieldErrors().stream()
                .findFirst()
                .map(fe -> fe.getField() + " " + fe.getDefaultMessage())
                .orElse("invalid request");
        return ResponseEntity.badRequest().body(Map.of("error", msg));
    }
}
