package io.github.openiqlibs.enums;

/**
 * This enum is providing defined roles object keys {@code realm_access} and {@code resource_access}
 */
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
