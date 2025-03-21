package com.sso4j.sso.defaults.auth;

import io.jsonwebtoken.Claims;
import com.sso4j.sso.enums.KeycloakScopes;
import com.sso4j.sso.token.auth.AbstractSSOTokenAndCerts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class DefaultKeycloakSSOTokenAndCerts extends AbstractSSOTokenAndCerts {

    private final Logger logger = LoggerFactory.getLogger(DefaultKeycloakSSOTokenAndCerts.class);

    private String keyCloakJwksUrl;

    @Override
    public String getSSO_JWKsUrl() {
        return keyCloakJwksUrl;
    }

    @Override
    public Set<String> getListOfRolesObjectKeys() {
        return Set.of(KeycloakScopes.REALM_ACCESS.getValue(), KeycloakScopes.RESOURCE_ACCESS.getValue());
    }

    public DefaultKeycloakSSOTokenAndCerts(String keyCloakJwksUrl) {
        this.keyCloakJwksUrl = keyCloakJwksUrl;
    }

    @Override
    protected Set<String> extractRoles(Claims claims) {
        Set<String> roles = new HashSet<>();
        for (String key : getListOfRolesObjectKeys()) {
            if (claims.containsKey(key) && key.equals(KeycloakScopes.RESOURCE_ACCESS.getValue())) {
                Map<String, Object> keyValueObj = (Map<String, Object>) claims.get(key);
                Map<String, Object> accountObj = (Map<String, Object>) keyValueObj.get("account");
                roles.addAll((Collection<String>) accountObj.get("roles"));
            } else if (claims.containsKey(key) && key.equals(KeycloakScopes.REALM_ACCESS.getValue())){
                Map<String, Object> keyValueObj = (Map<String, Object>) claims.get(key);
                roles.addAll((Collection<String>) keyValueObj.get("roles"));
            } else {
                logger.error("no roles found with key {}", key);
            }
        }
        return roles;
    }
}
