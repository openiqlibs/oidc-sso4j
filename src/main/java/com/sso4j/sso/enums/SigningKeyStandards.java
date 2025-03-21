package com.sso4j.sso.enums;

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
