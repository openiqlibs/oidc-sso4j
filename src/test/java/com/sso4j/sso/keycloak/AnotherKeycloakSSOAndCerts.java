package com.sso4j.sso.keycloak;

import com.sso4j.sso.token.auth.AbstractSSOTokenAndCerts;
import io.jsonwebtoken.Claims;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class AnotherKeycloakSSOAndCerts extends AbstractSSOTokenAndCerts {

    @Override
    public String getSSO_JWKsUrl() {
        return "http://localhost:8080/realms/testing/protocol/openid-connect/certs";
    }

    @Override
    public Set<String> getSetOfRolesObjectKeys() {
        return Set.of("notExist");
    }

    @Override
    protected Set<String> extractRoles(Claims claims) {
        Set<String> roles = new HashSet<>();
        for (String key : getSetOfRolesObjectKeys()) {
            if (claims.containsKey(key)) {
                Map<String, Object> keyObj = (Map<String, Object>) claims.get(key);
                roles.addAll((Collection<String>) keyObj.get("roles"));
            } else {
                System.out.println("no roles present with key " + key);
            }
        }
        return roles;
    }
}
