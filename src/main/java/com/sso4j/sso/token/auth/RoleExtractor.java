package com.sso4j.sso.token.auth;

import io.jsonwebtoken.Claims;

import java.util.Set;

public interface RoleExtractor {

    Set<String> extractRoles(Claims claims);
}
