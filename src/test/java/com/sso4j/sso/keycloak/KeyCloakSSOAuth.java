package com.sso4j.sso.keycloak;


import com.sso4j.sso.token.auth.AbstractSSOAuth;
import com.sso4j.sso.token.auth.AbstractSSOTokenAndCerts;

import java.util.Set;

public class KeyCloakSSOAuth extends AbstractSSOAuth {

    private final AbstractSSOTokenAndCerts keyCloakSSOAndCerts;

    public KeyCloakSSOAuth(AbstractSSOTokenAndCerts keyCloakSSOAndCerts) {
        this.keyCloakSSOAndCerts = keyCloakSSOAndCerts;
    }

    @Override
    public Set<String> verifyAndExtractRoles(String token) throws Exception {
        try {
            String kid = getKid(getHeaders(token));
            return keyCloakSSOAndCerts.getRolesOfToken(token, kid);
        } catch (Exception e) {
            throw e;
        }
    }
}
