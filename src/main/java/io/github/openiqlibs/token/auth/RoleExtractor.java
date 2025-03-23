package io.github.openiqlibs.token.auth;

import io.jsonwebtoken.Claims;

import java.util.Set;

/**
 * Interface RoleExtractor used in InAppTokenAndCerts class to extract roles from token
 * Needs to be implemented and passed implemented instance to InAppTokenAndCerts builder method {@code setRoleExtractor}
 */
public interface RoleExtractor {

    /**
    * Method can be implemented to extract roles from claims object
     * @param claims
     * @return Set<String>
    */
    Set<String> extractRoles(Claims claims);
}
