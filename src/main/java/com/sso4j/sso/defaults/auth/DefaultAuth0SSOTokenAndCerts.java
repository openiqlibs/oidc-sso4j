package com.sso4j.sso.defaults.auth;

import com.sso4j.sso.token.auth.AbstractSSOTokenAndCerts;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

public class DefaultAuth0SSOTokenAndCerts extends AbstractSSOTokenAndCerts {

    private final Logger logger = LoggerFactory.getLogger(DefaultAuth0SSOTokenAndCerts.class);

    private String auth0JwkssUrl;

    public DefaultAuth0SSOTokenAndCerts(String auth0JwkssUrl) {
        this.auth0JwkssUrl = auth0JwkssUrl;
    }

    @Override
    public String getSSO_JWKsUrl() {
        return auth0JwkssUrl;
    }

    @Override
    public Set<String> getListOfRolesObjectKeys() {
        return Set.of("scope");
    }

    @Override
    protected Set<String> extractRoles(Claims claims) {
        Set<String> roles = new HashSet<>();
        for (String key : getListOfRolesObjectKeys()) {
            if (claims.containsKey(key)) {
                String scopesList = claims.get(key).toString();
                roles.addAll(Arrays.stream(scopesList.split(" ")).collect(Collectors.toSet()));
            } else {
                logger.error("no roles present with key {}", key);
            }
        }
        return roles;
    }
}
