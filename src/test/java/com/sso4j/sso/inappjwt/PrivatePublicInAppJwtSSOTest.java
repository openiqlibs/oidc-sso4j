package com.sso4j.sso.inappjwt;

import com.sso4j.sso.enums.SigningKeyStandards;
import com.sso4j.sso.token.auth.InAppTokenAndCerts;

public class PrivatePublicInAppJwtSSOTest extends InAppJwtSSOTest{

    InAppTokenAndCerts inAppTokenAndCerts = new InAppTokenAndCerts.Builder()
            .setPrivateKeyString(System.getenv("privateKey"))
            .setPublicKeyString(System.getenv("publicKey"))
            .usingSigningKeyStandard(SigningKeyStandards.PUBLIC_KEY)
            .setIssuer("testing")
            .setAccessTokenValidityInMinutes(10)
            .setRefreshTokenValidityInHours(12)
            .build();

    InAppTokenAndCerts inAppDiffTokenAndCerts = new InAppTokenAndCerts.Builder()
            .setPrivateKeyString(System.getenv("privateKey2"))
            .setPublicKeyString(System.getenv("publicKey2"))
            .usingSigningKeyStandard(SigningKeyStandards.PUBLIC_KEY)
            .setIssuer("testing")
            .setAccessTokenValidityInMinutes(10)
            .setRefreshTokenValidityInHours(12)
            .build();

    InAppTokenAndCerts toExpiredTokenAndCerts = new InAppTokenAndCerts.Builder()
            .setPrivateKeyString(System.getenv("privateKey"))
            .setPublicKeyString(System.getenv("publicKey"))
            .usingSigningKeyStandard(SigningKeyStandards.PUBLIC_KEY)
            .setIssuer("testing")
            .setAccessTokenValidityInMinutes(1)
            .setRefreshTokenValidityInHours(12)
            .build();

    @Override
    public InAppTokenAndCerts getInAppTokenAndCertsWithSecretKey() {
        return inAppTokenAndCerts;
    }

    @Override
    public InAppTokenAndCerts getToTestExpiredToken() {
        return toExpiredTokenAndCerts;
    }

    @Override
    public InAppTokenAndCerts getInAppTokenAndCertsWithDiffSecretKey() {
        return inAppDiffTokenAndCerts;
    }
}
