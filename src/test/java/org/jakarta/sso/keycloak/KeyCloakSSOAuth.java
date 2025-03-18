package org.jakarta.sso.keycloak;


import org.jakarta.sso.token.auth.AbstractSSOAuth;
import org.jakarta.sso.token.auth.SSOTokenAndCerts;

import java.util.Set;

public class KeyCloakSSOAuth extends AbstractSSOAuth {

    private final SSOTokenAndCerts keyCloakSSOAndCerts;

    public KeyCloakSSOAuth(SSOTokenAndCerts keyCloakSSOAndCerts) {
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
