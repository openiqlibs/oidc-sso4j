package com.sso4j.sso.keycloak;

import com.sso4j.sso.token.auth.AbstractSSOTokenAndCerts;

import java.util.Set;

public class KeyCloakSSOAndCerts extends AbstractSSOTokenAndCerts {

    @Override
    public String getSSO_JWKsUrl() {
        return "http://localhost:8080/realms/testing/protocol/openid-connect/certs";
    }

    @Override
    public Set<String> getListOfRolesObjectKeys() {
        return Set.of("realm_access", "notExist");
    }
}
