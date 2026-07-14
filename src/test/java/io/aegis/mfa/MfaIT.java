package io.aegis.mfa;

import static io.aegis.commons.testing.AegisJwtTest.jwtForTenant;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import io.aegis.mfa.domain.WebAuthnAuditEvent;
import io.aegis.mfa.service.TotpGenerator;
import io.aegis.mfa.service.WebAuthnAuditService;
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
    @Autowired
    WebAuthnAuditService webAuthnAuditService;
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
    void webauthn_assert_options_are_issued() throws Exception {
        mockMvc.perform(post("/api/v1/mfa/internal/webauthn/assert/options")
                        .with(jwtForTenant("platform", "as-svc", "mfa:verify"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenant\":\"acme\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.challengeId").isNotEmpty())
                .andExpect(jsonPath("$.challenge").isNotEmpty())
                .andExpect(jsonPath("$.rpId").value("localhost"))
                .andExpect(jsonPath("$.userVerification").value("preferred"))
                .andExpect(jsonPath("$.allowCredentials").isArray());
    }

    @Test
    void webauthn_assert_options_accepts_a_blank_tenant() throws Exception {
        // The AS may not know the tenant yet (usernameless); a blank/absent tenant is allowed.
        mockMvc.perform(post("/api/v1/mfa/internal/webauthn/assert/options")
                        .with(jwtForTenant("platform", "as-svc", "mfa:verify"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenant\":\"\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.challengeId").isNotEmpty())
                .andExpect(jsonPath("$.challenge").isNotEmpty());
    }

    @Test
    void webauthn_assert_options_require_the_verify_scope() throws Exception {
        // A self-service token (no mfa:verify) must not reach the server-to-server assertion endpoint.
        mockMvc.perform(post("/api/v1/mfa/internal/webauthn/assert/options")
                        .with(jwtForTenant("acme", "u-1"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenant\":\"acme\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void webauthn_assert_options_require_a_token() throws Exception {
        mockMvc.perform(post("/api/v1/mfa/internal/webauthn/assert/options")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenant\":\"acme\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void webauthn_assert_verify_with_unknown_challenge_is_invalid_not_an_error() throws Exception {
        // A bogus challengeId + credentialId is a clean valid:false (200), never a 4xx/5xx.
        mockMvc.perform(post("/api/v1/mfa/internal/webauthn/assert/verify")
                        .with(jwtForTenant("platform", "as-svc", "mfa:verify"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{"
                                + "\"challengeId\":\"" + java.util.UUID.randomUUID() + "\","
                                + "\"credentialId\":\"AAAA\","
                                + "\"authenticatorData\":\"AAAA\","
                                + "\"clientDataJSON\":\"AAAA\","
                                + "\"signature\":\"AAAA\","
                                + "\"userHandle\":null}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.tenant").doesNotExist())
                .andExpect(jsonPath("$.subject").doesNotExist());
    }

    @Test
    void webauthn_assert_verify_with_a_real_challenge_but_unknown_credential_is_invalid() throws Exception {
        // Mint a real assertion challenge, then present an unknown credentialId -> valid:false.
        String options = mockMvc.perform(post("/api/v1/mfa/internal/webauthn/assert/options")
                        .with(jwtForTenant("platform", "as-svc", "mfa:verify"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenant\":\"acme\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String challengeId = JsonPath.read(options, "$.challengeId");

        mockMvc.perform(post("/api/v1/mfa/internal/webauthn/assert/verify")
                        .with(jwtForTenant("platform", "as-svc", "mfa:verify"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{"
                                + "\"challengeId\":\"" + challengeId + "\","
                                + "\"credentialId\":\"bm9zdWNoY3JlZA\","
                                + "\"authenticatorData\":\"AAAA\","
                                + "\"clientDataJSON\":\"AAAA\","
                                + "\"signature\":\"AAAA\","
                                + "\"userHandle\":null}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false));
    }

    @Test
    void webauthn_assert_verify_requires_the_verify_scope() throws Exception {
        mockMvc.perform(post("/api/v1/mfa/internal/webauthn/assert/verify")
                        .with(jwtForTenant("acme", "u-1"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{"
                                + "\"challengeId\":\"" + java.util.UUID.randomUUID() + "\","
                                + "\"credentialId\":\"AAAA\","
                                + "\"authenticatorData\":\"AAAA\","
                                + "\"clientDataJSON\":\"AAAA\","
                                + "\"signature\":\"AAAA\"}"))
                .andExpect(status().isForbidden());
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

    // --- Feature 1: per-tenant WebAuthn RP config (tenant-admin) ---

    @Test
    void webauthn_config_requires_a_token() throws Exception {
        mockMvc.perform(get("/api/v1/mfa/webauthn/config")).andExpect(status().isUnauthorized());
    }

    @Test
    void webauthn_config_requires_tenant_admin_scope() throws Exception {
        // A plain (non tenant:admin) token is authenticated but must not reach the admin config surface.
        mockMvc.perform(get("/api/v1/mfa/webauthn/config").with(jwtForTenant("acme", "u-1")))
                .andExpect(status().isForbidden());
    }

    @Test
    void webauthn_config_returns_global_defaults_when_absent() throws Exception {
        mockMvc.perform(get("/api/v1/mfa/webauthn/config")
                        .with(jwtForTenant("cfg-defaults", "admin", "tenant:admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rpId").value("localhost"))
                .andExpect(jsonPath("$.rpName").value("Aegis"))
                .andExpect(jsonPath("$.origins").isArray())
                .andExpect(jsonPath("$.userVerification").value("preferred"))
                .andExpect(jsonPath("$.authenticatorAttachment").value("any"))
                .andExpect(jsonPath("$.residentKey").value("preferred"))
                .andExpect(jsonPath("$.attestation").value("none"))
                .andExpect(jsonPath("$.enabled").value(true));
    }

    @Test
    void webauthn_config_can_be_upserted_and_read_back() throws Exception {
        String tenant = "cfg-upsert";
        mockMvc.perform(put("/api/v1/mfa/webauthn/config")
                        .with(jwtForTenant(tenant, "admin", "tenant:admin"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"rpId\":\"acme.example.com\","
                                + "\"rpName\":\"Acme\","
                                + "\"origins\":[\"https://app.acme.com\"],"
                                + "\"userVerification\":\"required\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rpId").value("acme.example.com"))
                .andExpect(jsonPath("$.origins[0]").value("https://app.acme.com"))
                .andExpect(jsonPath("$.userVerification").value("required"));

        // GET reflects the saved config.
        mockMvc.perform(get("/api/v1/mfa/webauthn/config")
                        .with(jwtForTenant(tenant, "admin", "tenant:admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rpId").value("acme.example.com"))
                .andExpect(jsonPath("$.origins[0]").value("https://app.acme.com"))
                .andExpect(jsonPath("$.userVerification").value("required"));
    }

    @Test
    void webauthn_config_rejects_an_invalid_user_verification() throws Exception {
        mockMvc.perform(put("/api/v1/mfa/webauthn/config")
                        .with(jwtForTenant("cfg-bad", "admin", "tenant:admin"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"rpId\":\"acme.example.com\","
                                + "\"origins\":[\"https://app.acme.com\"],"
                                + "\"userVerification\":\"sometimes\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void webauthn_config_rejects_a_blank_rp_id() throws Exception {
        mockMvc.perform(put("/api/v1/mfa/webauthn/config")
                        .with(jwtForTenant("cfg-blank", "admin", "tenant:admin"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"rpId\":\"\",\"origins\":[\"https://app.acme.com\"]}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void webauthn_config_is_tenant_scoped() throws Exception {
        // Tenant A sets a custom rpId; tenant B still sees the global defaults.
        mockMvc.perform(put("/api/v1/mfa/webauthn/config")
                        .with(jwtForTenant("cfg-iso-a", "admin", "tenant:admin"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"rpId\":\"a.example.com\",\"origins\":[\"https://a.example.com\"]}"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/v1/mfa/webauthn/config")
                        .with(jwtForTenant("cfg-iso-b", "admin", "tenant:admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rpId").value("localhost"));
    }

    // --- Feature 2: WebAuthn audit (tenant-admin) ---

    @Test
    void webauthn_audit_requires_a_token() throws Exception {
        mockMvc.perform(get("/api/v1/mfa/webauthn/audit")).andExpect(status().isUnauthorized());
    }

    @Test
    void webauthn_audit_requires_tenant_admin_scope() throws Exception {
        mockMvc.perform(get("/api/v1/mfa/webauthn/audit").with(jwtForTenant("acme", "u-1")))
                .andExpect(status().isForbidden());
    }

    @Test
    void webauthn_audit_returns_an_array() throws Exception {
        mockMvc.perform(get("/api/v1/mfa/webauthn/audit")
                        .with(jwtForTenant("audit-empty", "admin", "tenant:admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }

    @Test
    void webauthn_audit_surfaces_recorded_events_newest_first_and_is_tenant_scoped() throws Exception {
        String tenant = "audit-populated";
        // Record two events directly (a full ceremony needs a browser authenticator).
        webAuthnAuditService.record(tenant, "user-a", WebAuthnAuditEvent.PASSKEY_REGISTERED,
                "cred-1", "aaguid-1", "MacBook");
        webAuthnAuditService.record(tenant, "user-a", WebAuthnAuditEvent.PASSKEY_REMOVED,
                "cred-1", "aaguid-1", null);
        // A different tenant's event must never leak into this tenant's view.
        webAuthnAuditService.record("other-tenant", "user-x", WebAuthnAuditEvent.PASSKEY_AUTHENTICATED,
                "cred-x", null, null);

        mockMvc.perform(get("/api/v1/mfa/webauthn/audit")
                        .with(jwtForTenant(tenant, "admin", "tenant:admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].action").value("PASSKEY_REMOVED"))
                .andExpect(jsonPath("$[0].subject").value("user-a"))
                .andExpect(jsonPath("$[0].credentialId").value("cred-1"))
                .andExpect(jsonPath("$[1].action").value("PASSKEY_REGISTERED"))
                .andExpect(jsonPath("$[1].aaguid").value("aaguid-1"));
    }

    // --- Feature 3: tenant-app WebAuthn ceremony uses the tenant's OWN RP config ---

    /** PUT a custom RP config for a tenant, as a tenant:admin would during setup. */
    private void putCustomConfig(String tenant, String rpId, String origin) throws Exception {
        mockMvc.perform(put("/api/v1/mfa/webauthn/config")
                        .with(jwtForTenant(tenant, "admin", "tenant:admin"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"rpId\":\"" + rpId + "\",\"origins\":[\"" + origin + "\"]}"))
                .andExpect(status().isOk());
    }

    @Test
    void internal_register_options_use_the_tenants_own_rp_when_configured() throws Exception {
        String tenant = "rp-custom";
        putCustomConfig(tenant, "acme.example.com", "https://app.acme.com");

        // The AS (mfa:verify) drives registration for the tenant's app; options carry the tenant's rpId.
        mockMvc.perform(post("/api/v1/mfa/internal/webauthn/register/options")
                        .with(jwtForTenant("platform", "as-svc", "mfa:verify"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenant\":\"" + tenant + "\",\"subject\":\"u-1\","
                                + "\"userName\":\"alice@acme.com\",\"displayName\":\"Alice\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rp.id").value("acme.example.com"))
                .andExpect(jsonPath("$.user.name").value("alice@acme.com"))
                .andExpect(jsonPath("$.user.displayName").value("Alice"))
                .andExpect(jsonPath("$.challenge").isNotEmpty())
                .andExpect(jsonPath("$.pubKeyCredParams[0].alg").value(-7));
    }

    @Test
    void internal_register_options_fall_back_to_global_rp_for_a_plain_tenant() throws Exception {
        // A tenant with no custom config gets the global rpId (localhost) — hosted behaviour is unchanged.
        mockMvc.perform(post("/api/v1/mfa/internal/webauthn/register/options")
                        .with(jwtForTenant("platform", "as-svc", "mfa:verify"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenant\":\"rp-plain\",\"subject\":\"u-2\","
                                + "\"userName\":\"bob\",\"displayName\":\"Bob\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rp.id").value("localhost"));
    }

    @Test
    void internal_register_options_require_the_verify_scope() throws Exception {
        // A self-service token (no mfa:verify) must not reach the internal registration endpoint.
        mockMvc.perform(post("/api/v1/mfa/internal/webauthn/register/options")
                        .with(jwtForTenant("rp-custom", "u-1"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenant\":\"rp-custom\",\"subject\":\"u-1\","
                                + "\"userName\":\"a\",\"displayName\":\"A\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void internal_register_options_require_a_token() throws Exception {
        mockMvc.perform(post("/api/v1/mfa/internal/webauthn/register/options")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenant\":\"rp-custom\",\"subject\":\"u-1\","
                                + "\"userName\":\"a\",\"displayName\":\"A\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void internal_register_finish_without_a_challenge_is_a_400() throws Exception {
        // No register/options was called for this (tenant, subject), so there is no challenge in progress:
        // the finish ceremony (structurally exercised) rejects it as a 400 via MfaExceptionHandler.
        mockMvc.perform(post("/api/v1/mfa/internal/webauthn/register/finish")
                        .with(jwtForTenant("platform", "as-svc", "mfa:verify"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenant\":\"rp-custom\",\"subject\":\"no-challenge\","
                                + "\"attestationObject\":\"AAAA\",\"clientDataJSON\":\"AAAA\",\"label\":\"Test\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void internal_register_finish_with_a_bad_attestation_is_a_400() throws Exception {
        // Mint a real registration challenge, then present garbage attestation bytes -> the webauthn4j
        // verification fails and surfaces as a 400 (the crypto path is exercised structurally).
        String tenant = "rp-finish";
        putCustomConfig(tenant, "finish.example.com", "https://finish.example.com");
        mockMvc.perform(post("/api/v1/mfa/internal/webauthn/register/options")
                        .with(jwtForTenant("platform", "as-svc", "mfa:verify"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenant\":\"" + tenant + "\",\"subject\":\"u-fin\","
                                + "\"userName\":\"a\",\"displayName\":\"A\"}"))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/v1/mfa/internal/webauthn/register/finish")
                        .with(jwtForTenant("platform", "as-svc", "mfa:verify"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenant\":\"" + tenant + "\",\"subject\":\"u-fin\","
                                + "\"attestationObject\":\"AAAA\",\"clientDataJSON\":\"AAAA\",\"label\":\"Test\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void internal_register_finish_requires_the_verify_scope() throws Exception {
        mockMvc.perform(post("/api/v1/mfa/internal/webauthn/register/finish")
                        .with(jwtForTenant("rp-custom", "u-1"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenant\":\"rp-custom\",\"subject\":\"u-1\","
                                + "\"attestationObject\":\"AAAA\",\"clientDataJSON\":\"AAAA\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void internal_assert_options_use_the_tenants_own_rp_when_configured() throws Exception {
        String tenant = "rp-assert";
        putCustomConfig(tenant, "assert.example.com", "https://assert.example.com");

        mockMvc.perform(post("/api/v1/mfa/internal/webauthn/assert/options")
                        .with(jwtForTenant("platform", "as-svc", "mfa:verify"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"tenant\":\"" + tenant + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rpId").value("assert.example.com"))
                .andExpect(jsonPath("$.challengeId").isNotEmpty());
    }
}
