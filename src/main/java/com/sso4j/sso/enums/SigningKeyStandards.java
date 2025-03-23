package com.sso4j.sso.enums;

/**
 * This enum is providing keys {@code secretKey} and {@code publicKey} in generate token method and
 * also can be helpful while retrieving access token and refresh token from taken pair map
 */
public enum SigningKeyStandards {
    SECRET_KEY("secretKey"),
    PUBLIC_KEY("publicKey");

    private final String keyType;

    SigningKeyStandards(String keyType) {
        this.keyType = keyType;
    }

    public String getValue() {
        return keyType;
    }
}
