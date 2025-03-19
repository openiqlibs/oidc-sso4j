package org.jakarta.sso.enums;

public enum KeycloakScopes {

    REALM_ACCESS("realm_access"),
    RESOURCE_ACCESS("resource_access");

    private String value;

    KeycloakScopes(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
