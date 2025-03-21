package com.sso4j.sso.keycloak;

import com.sso4j.sso.token.auth.SSOTokenAndCerts;

import java.util.Set;

public class KeyCloakSSOAndCerts extends SSOTokenAndCerts {

    @Override
    protected String getSSO_JWKsUrl() {
        return "http://localhost:8080/realms/testing/protocol/openid-connect/certs";
    }

    @Override
    protected Set<String> getListOfRolesObjectKeys() {
        return Set.of("realm_access", "notExist");
    }
}
