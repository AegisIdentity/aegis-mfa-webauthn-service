--
-- Baseline schema for mfa-webauthn-service.
--
-- GENERATED from the JPA entities by Hibernate's schema exporter, not hand-written. The service
-- runs with ddl-auto: validate, so any drift between this file and the entities fails startup —
-- generating it is what guarantees the two agree.
--
-- Regenerate after an entity change (then add a NEW V<n>__ migration; never edit an applied one):
--   mvn -o verify -Dit.test=<AnIT> -DfailIfNoSpecifiedTests=false \
--     -Dspring.jpa.properties.jakarta.persistence.schema-generation.scripts.action=create \
--     -Dspring.jpa.properties.jakarta.persistence.schema-generation.scripts.create-target=target/generated-schema.sql
--
-- Existing (pre-Flyway) databases are handled by flyway.baseline-on-migrate=true: they are marked
-- at the baseline version and this migration is skipped, since their tables already exist.
--
create table totp_credential (enabled boolean not null, created_at timestamp(6) with time zone not null, last_used_at timestamp(6) with time zone, id uuid not null, secret_base32 varchar(255) not null, subject varchar(255) not null, tenant_id varchar(255) not null, primary key (id), constraint uq_totp_tenant_subject unique (tenant_id, subject));

create table webauthn_audit_event (at timestamp(6) with time zone not null, id uuid not null, action varchar(32) not null, aaguid varchar(64), credential_id varchar(512), detail varchar(512), subject varchar(255), tenant_id varchar(255) not null, primary key (id));

create table webauthn_challenge (expires_at timestamp(6) with time zone not null, id uuid not null, type varchar(16) not null check ((type in ('REGISTRATION','ASSERTION'))), challenge varchar(128) not null, subject varchar(255) not null, tenant_id varchar(255) not null, primary key (id));

create table webauthn_credential (created_at timestamp(6) with time zone not null, last_used_at timestamp(6) with time zone, sign_count bigint not null, id uuid not null, aaguid varchar(64), label varchar(120) not null, credential_id varchar(512) not null, subject varchar(255) not null, tenant_id varchar(255) not null, public_key_cose bytea not null, primary key (id), constraint uq_webauthn_credential_id unique (credential_id));

create table webauthn_tenant_config (enabled boolean not null, updated_at timestamp(6) with time zone not null, attestation varchar(16) not null, authenticator_attachment varchar(16) not null, resident_key varchar(16) not null, user_verification varchar(16) not null, tenant_id varchar(64) not null, origins varchar(2048) not null, rp_id varchar(255) not null, rp_name varchar(255) not null, primary key (tenant_id));

create index ix_webauthn_audit_tenant on webauthn_audit_event (tenant_id);

