package com.sso4j.sso.auth0;

import com.sso4j.sso.token.auth.AbstractSSOTokenAndCerts;
import io.jsonwebtoken.Claims;

import java.util.*;
import java.util.stream.Collectors;

public class Auth0SSOTokenAndCerts extends AbstractSSOTokenAndCerts {

    @Override
    public String getSSO_JWKsUrl() {
        return System.getenv("auth0_domain") + "/.well-known/jwks.json";
    }

    @Override
    public Set<String> getSetOfRolesObjectKeys() {
        return Set.of("scope");
    }

    @Override
    protected Set<String> extractRoles(Claims claims) {
        Set<String> roles = new HashSet<>();
        for (String key : getSetOfRolesObjectKeys()) {
            if (claims.containsKey(key)) {
                String rolesString = claims.get(key).toString();
                roles.addAll(Arrays.stream(rolesString.split(" ")).collect(Collectors.toSet()));
            } else {
                System.out.println("no roles present with key " + key);
            }
        }
        return roles;
    }
}
