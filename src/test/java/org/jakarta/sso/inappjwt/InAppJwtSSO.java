package org.jakarta.sso.inappjwt;

import io.jsonwebtoken.Claims;
import org.jakarta.sso.enums.SigningKeyStandards;
import org.jakarta.sso.token.auth.AbstractSSOAuth;
import org.jakarta.sso.token.auth.InAppTokenAndCerts;

import java.util.Set;

public class InAppJwtSSO extends AbstractSSOAuth {

    InAppTokenAndCerts inAppTokenAndCertsWithSecretKey = new InAppTokenAndCerts.Builder()
            .setSecretValue("nlcksncjdksjiefowhuhdiuwgdyfewghcdfcuwgdikqjdknjwchkuehwyuvxctywev")
            .usingSigningKeyStandard(SigningKeyStandards.SECRET_KEY)
            .setIssuer("testing")
            .setAccessTokenValidityInMinutes(10)
            .setRefreshTokenValidityInHours(12)
            .build();

    @Override
    public Set<String> verifyAndExtractRoles(String token) throws Exception {
        try {
             return inAppTokenAndCertsWithSecretKey.getRolesOfToken(token);
        } catch (Exception e) {
            throw e;
        }
    }
}
