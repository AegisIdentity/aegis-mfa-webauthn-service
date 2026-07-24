package io.aegis.mfa.crypto;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

/**
 * JPA converter that transparently AES-256-GCM encrypts a String column at rest via {@link FieldEncryption}.
 * Applied explicitly (not {@code autoApply}) to sensitive fields — e.g. the TOTP shared secret (H5).
 */
@Converter
public class EncryptedStringConverter implements AttributeConverter<String, String> {

    @Override
    public String convertToDatabaseColumn(String attribute) {
        return FieldEncryption.encrypt(attribute);
    }

    @Override
    public String convertToEntityAttribute(String dbData) {
        return FieldEncryption.decrypt(dbData);
    }
}
