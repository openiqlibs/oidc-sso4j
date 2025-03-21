package com.sso4j.sso.inappjwt;

import com.sso4j.sso.enums.SigningKeyStandards;
import com.sso4j.sso.token.auth.InAppTokenAndCerts;

public class SecretKeyInAppJwtSSOTest extends InAppJwtSSOTest{

    InAppTokenAndCerts inAppTokenAndCertsWithSecretKey = new InAppTokenAndCerts.Builder()
            .setSecretValue("nlcksncjdksjiefowhuhdiuwgdyfewghcdfcuwgdikqjdknjwchkuehwyuvxctywev")
            .usingSigningKeyStandard(SigningKeyStandards.SECRET_KEY)
            .setIssuer("testing")
            .setAudience("testing")
            .setAccessTokenValidityInMinutes(10)
            .setRefreshTokenValidityInHours(12)
            .build();

    InAppTokenAndCerts toTestExpiredToken = new InAppTokenAndCerts.Builder()
            .setSecretValue("nlcksncjdksjiefowhuhdiuwgdyfewghcdfcuwgdikqjdknjwchkuehwyuvxctywev")
            .usingSigningKeyStandard(SigningKeyStandards.SECRET_KEY)
            .setIssuer("testing")
            .setAudience("testing")
            .setAccessTokenValidityInMinutes(1)
            .setRefreshTokenValidityInHours(12)
            .build();

    InAppTokenAndCerts inAppTokenAndCertsWithDiffSecretKey = new InAppTokenAndCerts.Builder()
            .setSecretValue("nlcksncjdksjiefowhuhdkiwgdyfewghcdfcuwgdikqjdknjwchkuehwyuvxctywev")
            .usingSigningKeyStandard(SigningKeyStandards.SECRET_KEY)
            .setIssuer("testing")
            .setAudience("testing")
            .setAccessTokenValidityInMinutes(10)
            .setRefreshTokenValidityInHours(12)
            .build();

    @Override
    public InAppTokenAndCerts getInAppTokenAndCertsWithSecretKey() {
        return inAppTokenAndCertsWithSecretKey;
    }

    @Override
    public InAppTokenAndCerts getToTestExpiredToken() {
        return toTestExpiredToken;
    }

    @Override
    public InAppTokenAndCerts getInAppTokenAndCertsWithDiffSecretKey() {
        return inAppTokenAndCertsWithDiffSecretKey;
    }
}
