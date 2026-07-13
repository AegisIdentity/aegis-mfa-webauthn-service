package io.aegis.mfa;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Placeholder protected endpoint so the security baseline is exercised end to end. */
@RestController
public class InfoController {

    @GetMapping("/api/v1/mfa/info")
    public Map<String, String> info() {
        return Map.of("service", "aegis-mfa-webauthn-service", "maturity", "scaffold");
    }
}
