package io.github.openiqlibs.auth0;

import io.github.openiqlibs.token.auth.AbstractSSOAuth;

import java.util.Set;

public class Auth0SSOAuth extends AbstractSSOAuth {

    Auth0SSOTokenAndCerts auth0SSOTokenAndCerts;

    public Auth0SSOAuth(Auth0SSOTokenAndCerts auth0SSOTokenAndCerts) {
        this.auth0SSOTokenAndCerts = auth0SSOTokenAndCerts;
    }

    @Override
    public Set<String> verifyAndExtractRoles(String token) throws Exception {
        try {
            String kid = getKid(getHeaders(token));
            return auth0SSOTokenAndCerts.getRolesOfToken(token, kid);
        } catch (Exception e) {
            throw e;
        }
    }
}
