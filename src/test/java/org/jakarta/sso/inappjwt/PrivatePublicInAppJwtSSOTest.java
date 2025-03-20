package org.jakarta.sso.inappjwt;

import org.jakarta.sso.enums.SigningKeyStandards;
import org.jakarta.sso.token.auth.InAppTokenAndCerts;

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
            .setPrivateKeyString(System.getenv("privateKey"))
            .setPublicKeyString(System.getenv("publicKey"))
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
            .setAccessTokenValidityInMinutes(10)
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
