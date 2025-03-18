package org.jakarta.sso.keycloak;

import org.jakarta.sso.token.auth.SSOTokenAndCerts;

import java.util.Set;

public class NotExistRealmSSOAndCerts extends SSOTokenAndCerts {

    @Override
    public String getSSO_JWKsUrl() {
        return "http://localhost:8080/realms/notExist/protocol/openid-connect/certs";
    }

    @Override
    public Set<String> getListOfRolesObjectKeys() {
        return Set.of("realm_access");
    }
}
