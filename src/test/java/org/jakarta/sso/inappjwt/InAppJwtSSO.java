package org.jakarta.sso.inappjwt;

import org.jakarta.sso.enums.SigningKeyStandards;
import org.jakarta.sso.token.auth.AbstractSSOAuth;
import org.jakarta.sso.token.auth.InAppTokenAndCerts;

import java.util.Set;

public class InAppJwtSSO extends AbstractSSOAuth {

    InAppTokenAndCerts inAppTokenAndCerts = new InAppTokenAndCerts.Builder()
            .setSecretValue("nlcksncjdksjiefowhuhdiuwgdyfewghcdfcuwgdikqjdknjwchkuehwyuvxctywev")
            .usingSigningKeyStandard(SigningKeyStandards.SECRET_KEY)
            .setAccessTokenValidityInMinutes(10)
            .setRefreshTokenValidityInHours(12)
            .build();


    @Override
    public Set<String> verifyAndExtractRoles(String token) throws Exception {
        try {

        } catch (Exception e) {

        }
        return Set.of();
    }
}
