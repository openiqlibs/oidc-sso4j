package com.sso4j.sso.token.auth;


import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Class is default implementation of RoleExtractor interface
 */
public class DefaultRoleExtractor implements RoleExtractor {

    private Logger logger = LoggerFactory.getLogger(DefaultRoleExtractor.class);

    @Override
    public Set<String> extractRoles(Claims claims) {
        Set<String> roles = new HashSet<>();
        if (claims.containsKey("roles")) {
            roles.addAll((Collection<String>) claims.get("roles"));
        } else {
            logger.error("no 'roles' key present to extract roles from claims");
        }
        return roles;
    }
}
