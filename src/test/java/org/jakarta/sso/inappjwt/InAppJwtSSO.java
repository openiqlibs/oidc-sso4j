package org.jakarta.sso.inappjwt;

import org.jakarta.sso.token.auth.AbstractSSOAuth;
import org.jakarta.sso.token.auth.InAppTokenAndCerts;

import java.util.Set;

public class InAppJwtSSO extends AbstractSSOAuth {

    InAppTokenAndCerts inAppTokenAndCertsWithSecretKey;

    public InAppJwtSSO(InAppTokenAndCerts inAppTokenAndCertsWithSecretKey) {
        this.inAppTokenAndCertsWithSecretKey = inAppTokenAndCertsWithSecretKey;
    }

    @Override
    public Set<String> verifyAndExtractRoles(String token) throws Exception {
        try {
             return inAppTokenAndCertsWithSecretKey.getRolesOfToken(token);
        } catch (Exception e) {
            throw e;
        }
    }
}
