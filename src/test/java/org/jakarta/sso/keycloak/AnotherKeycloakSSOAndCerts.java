package org.jakarta.sso.keycloak;

import org.jakarta.sso.token.auth.SSOTokenAndCerts;

import java.util.Set;

public class AnotherKeycloakSSOAndCerts extends SSOTokenAndCerts {

    @Override
    public String getSSO_JWKsUrl() {
        return "http://localhost:8080/realms/testing/protocol/openid-connect/certs";
    }

    @Override
    public Set<String> getListOfRolesObjectKeys() {
        return Set.of("not_present");
    }
}
