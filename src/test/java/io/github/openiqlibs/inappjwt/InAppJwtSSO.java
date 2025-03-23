package io.github.openiqlibs.inappjwt;

import io.github.openiqlibs.token.auth.AbstractSSOAuth;
import io.github.openiqlibs.token.auth.InAppTokenAndCerts;

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
