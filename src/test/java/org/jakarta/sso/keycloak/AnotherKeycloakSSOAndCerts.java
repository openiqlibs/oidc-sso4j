package org.jakarta.sso.keycloak;

import org.jakarta.sso.token.auth.SSOTokenAndCerts;

import java.util.Set;

public class AnotherKeycloakSSOAndCerts extends SSOTokenAndCerts {

    @Override
    protected String getSSO_JWKsUrl() {
        return "http://localhost:8080/realms/testing/protocol/openid-connect/certs";
    }

    @Override
    protected Set<String> getListOfRolesObjectKeys() {
        return Set.of("notExist");
    }
}
