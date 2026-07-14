package io.aegis.mfa;

import static io.aegis.commons.testing.AegisJwtTest.jwtForTenant;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import io.aegis.mfa.service.TotpGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * End-to-end MFA API tests against a real Postgres: the security baseline (default-deny, scope gates)
 * and the full TOTP enrol → verify → step-up lifecycle, plus tenant isolation. Passkey registration
 * only exercises option generation here — the attestation ceremony needs a real browser authenticator.
 */
@SpringBootTest
@Import(MfaTestConfig.class)
class MfaIT {

    @Autowired
    WebApplicationContext context;
    MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    @Test
    void health_is_public() throws Exception {
        mockMvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }

    @Test
    void self_service_requires_a_token() throws Exception {
        mockMvc.perform(get("/api/v1/mfa/factors")).andExpect(status().isUnauthorized());
    }

    @Test
    void internal_step_up_requires_the_verify_scope() throws Exception {
        // A self-service token (no mfa:verify) must not reach the server-to-server endpoints.
        mockMvc.perform(get("/api/v1/mfa/internal/status")
                        .param("tenant", "acme").param("subject", "u-1")
                        .with(jwtForTenant("acme", "svc")))
                .andExpect(status().isForbidden());
        // The AS service token carrying mfa:verify may.
        mockMvc.perform(get("/api/v1/mfa/internal/status")
                        .param("tenant", "acme").param("subject", "u-1")
                        .with(jwtForTenant("acme", "svc", "mfa:verify")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enrolled").value(false));
    }

    @Test
    void totp_enrol_verify_and_step_up_lifecycle() throws Exception {
        String tenant = "acme";
        String subject = "user-totp-1";

        // 1) Enrol: get a secret + otpauth URI. Not yet enabled.
        String enrollBody = mockMvc.perform(post("/api/v1/mfa/totp/enroll")
                        .with(jwtForTenant(tenant, subject)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.secret").isNotEmpty())
                .andExpect(jsonPath("$.otpauthUri", org.hamcrest.Matchers.startsWith("otpauth://totp/")))
                .andReturn().getResponse().getContentAsString();
        String secret = JsonPath.read(enrollBody, "$.secret");

        mockMvc.perform(get("/api/v1/mfa/factors").with(jwtForTenant(tenant, subject)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totp.enabled").value(false));

        // 2) A wrong code is rejected.
        mockMvc.perform(post("/api/v1/mfa/totp/verify")
                        .with(jwtForTenant(tenant, subject))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"code\":\"000000\"}"))
                .andExpect(status().isBadRequest());

        // 3) A live code enables the factor.
        String code = TotpGenerator.code(secret, System.currentTimeMillis(), 6, 30);
        mockMvc.perform(post("/api/v1/mfa/totp/verify")
                        .with(jwtForTenant(tenant, subject))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"code\":\"" + code + "\"}"))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/v1/mfa/factors").with(jwtForTenant(tenant, subject)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totp.enabled").value(true));

        // 4) Step-up (server-to-server) reports enrolment and validates a live code.
        mockMvc.perform(get("/api/v1/mfa/internal/status")
                        .param("tenant", tenant).param("subject", subject)
                        .with(jwtForTenant("platform", "as-svc", "mfa:verify")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enrolled").value(true))
                .andExpect(jsonPath("$.methods[0]").value("totp"));

        String stepUpCode = TotpGenerator.code(secret, System.currentTimeMillis(), 6, 30);
        mockMvc.perform(post("/api/v1/mfa/internal/totp/validate")
                        .with(jwtForTenant("platform", "as-svc", "mfa:verify"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenant\":\"" + tenant + "\",\"subject\":\"" + subject
                                + "\",\"code\":\"" + stepUpCode + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true));

        // 5) A bad step-up code is rejected (valid:false, not an error).
        mockMvc.perform(post("/api/v1/mfa/internal/totp/validate")
                        .with(jwtForTenant("platform", "as-svc", "mfa:verify"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenant\":\"" + tenant + "\",\"subject\":\"" + subject
                                + "\",\"code\":\"111111\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false));
    }

    @Test
    void internal_force_enrol_lifecycle() throws Exception {
        String tenant = "acme";
        String subject = "user-force-enrol";

        // Without the mfa:verify scope, force-enrol is forbidden.
        mockMvc.perform(post("/api/v1/mfa/internal/totp/enroll")
                        .with(jwtForTenant(tenant, subject))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenant\":\"" + tenant + "\",\"subject\":\"" + subject
                                + "\",\"account\":\"" + subject + "\"}"))
                .andExpect(status().isForbidden());

        // With no token at all, unauthorized.
        mockMvc.perform(post("/api/v1/mfa/internal/totp/enroll")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenant\":\"" + tenant + "\",\"subject\":\"" + subject
                                + "\",\"account\":\"" + subject + "\"}"))
                .andExpect(status().isUnauthorized());

        // 1) The AS service token (mfa:verify) force-enrols on the user's behalf: gets a secret. Not yet enabled.
        String enrollBody = mockMvc.perform(post("/api/v1/mfa/internal/totp/enroll")
                        .with(jwtForTenant("platform", "as-svc", "mfa:verify"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenant\":\"" + tenant + "\",\"subject\":\"" + subject
                                + "\",\"account\":\"" + subject + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.secret").isNotEmpty())
                .andExpect(jsonPath("$.otpauthUri", org.hamcrest.Matchers.startsWith("otpauth://totp/")))
                .andReturn().getResponse().getContentAsString();
        String secret = JsonPath.read(enrollBody, "$.secret");

        // 2) A wrong code at verify-enable is rejected with 400 (not caught by the controller).
        mockMvc.perform(post("/api/v1/mfa/internal/totp/verify-enable")
                        .with(jwtForTenant("platform", "as-svc", "mfa:verify"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenant\":\"" + tenant + "\",\"subject\":\"" + subject
                                + "\",\"code\":\"000000\"}"))
                .andExpect(status().isBadRequest());

        // 3) A live code confirms the enrolment and activates the factor -> 204.
        String code = TotpGenerator.code(secret, System.currentTimeMillis(), 6, 30);
        mockMvc.perform(post("/api/v1/mfa/internal/totp/verify-enable")
                        .with(jwtForTenant("platform", "as-svc", "mfa:verify"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenant\":\"" + tenant + "\",\"subject\":\"" + subject
                                + "\",\"code\":\"" + code + "\"}"))
                .andExpect(status().isNoContent());

        // 4) Status now reports the user enrolled with TOTP.
        mockMvc.perform(get("/api/v1/mfa/internal/status")
                        .param("tenant", tenant).param("subject", subject)
                        .with(jwtForTenant("platform", "as-svc", "mfa:verify")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enrolled").value(true))
                .andExpect(jsonPath("$.methods[0]").value("totp"));
    }

    @Test
    void totp_is_tenant_isolated() throws Exception {
        String subject = "shared-subject";
        // Enrol + enable in tenant A.
        String body = mockMvc.perform(post("/api/v1/mfa/totp/enroll").with(jwtForTenant("tenant-a", subject)))
                .andReturn().getResponse().getContentAsString();
        String secret = JsonPath.read(body, "$.secret");
        String code = TotpGenerator.code(secret, System.currentTimeMillis(), 6, 30);
        mockMvc.perform(post("/api/v1/mfa/totp/verify").with(jwtForTenant("tenant-a", subject))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"code\":\"" + code + "\"}"))
                .andExpect(status().isNoContent());

        // Tenant B with the same subject id sees no TOTP.
        mockMvc.perform(get("/api/v1/mfa/factors").with(jwtForTenant("tenant-b", subject)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totp").doesNotExist());
    }

    @Test
    void passkey_registration_options_are_issued() throws Exception {
        String options = mockMvc.perform(post("/api/v1/mfa/webauthn/register/options")
                        .with(jwtForTenant("acme", "user-wa-1")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.challenge").isNotEmpty())
                .andExpect(jsonPath("$.rp.id").value("localhost"))
                .andExpect(jsonPath("$.user.name").value("user-wa-1"))
                .andReturn().getResponse().getContentAsString();
        // ES256 must be offered.
        assertThat(options).contains("-7");
    }

    @Test
    void totp_can_be_removed() throws Exception {
        String subject = "user-remove";
        mockMvc.perform(post("/api/v1/mfa/totp/enroll").with(jwtForTenant("acme", subject)))
                .andExpect(status().isOk());
        mockMvc.perform(delete("/api/v1/mfa/totp").with(jwtForTenant("acme", subject)))
                .andExpect(status().isNoContent());
        mockMvc.perform(get("/api/v1/mfa/factors").with(jwtForTenant("acme", subject)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totp").doesNotExist());
    }
}
