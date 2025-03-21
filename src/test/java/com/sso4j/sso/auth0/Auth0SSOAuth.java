package com.sso4j.sso.auth0;

import com.sso4j.sso.defaults.auth.DefaultAuth0SSOTokenAndCerts;
import com.sso4j.sso.token.auth.AbstractSSOAuth;

import java.util.Set;

public class Auth0SSOAuth extends AbstractSSOAuth {

    DefaultAuth0SSOTokenAndCerts defaultAuth0SSOTokenAndCerts;

    public Auth0SSOAuth(DefaultAuth0SSOTokenAndCerts defaultAuth0SSOTokenAndCerts) {
        this.defaultAuth0SSOTokenAndCerts = defaultAuth0SSOTokenAndCerts;
    }

    @Override
    public Set<String> verifyAndExtractRoles(String token) throws Exception {
        try {
            String kid = getKid(getHeaders(token));
            return defaultAuth0SSOTokenAndCerts.getRolesOfToken(token, kid);
        } catch (Exception e) {
            throw e;
        }
    }
}
