package io.github.openiqlibs.inappjwt;

import io.github.openiqlibs.enums.SigningKeyStandards;
import io.github.openiqlibs.token.auth.InAppTokenAndCerts;

import java.util.*;

public class PrivatePublicInAppJwtSSOTest extends InAppJwtSSOTest{

    public Map<String, Map<String, Object>> inMemDatabase = new HashMap<>();

    InAppTokenAndCerts inAppTokenAndCerts = new InAppTokenAndCerts.Builder()
            .setPrivateKeyString(System.getenv("privateKey"))
            .setPublicKeyString(System.getenv("publicKey"))
            .usingSigningKeyStandard(SigningKeyStandards.PUBLIC_KEY)
            .setAudience("testing")
            .setIssuer("testing")
            .setAccessTokenValidityInMinutes(10)
            .setRefreshTokenValidityInHours(12)
            .build();

    InAppTokenAndCerts inAppDiffTokenAndCerts = new InAppTokenAndCerts.Builder()
            .setPrivateKeyString(System.getenv("privateKey2"))
            .setPublicKeyString(System.getenv("publicKey2"))
            .usingSigningKeyStandard(SigningKeyStandards.PUBLIC_KEY)
            .setIssuer("testing")
            .setAudience("testing")
            .setAccessTokenValidityInMinutes(10)
            .setRefreshTokenValidityInHours(12)
            .build();

    InAppTokenAndCerts toExpiredTokenAndCerts = new InAppTokenAndCerts.Builder()
            .setPrivateKeyString(System.getenv("privateKey"))
            .setPublicKeyString(System.getenv("publicKey"))
            .usingSigningKeyStandard(SigningKeyStandards.PUBLIC_KEY)
            .setIssuer("testing")
            .setAudience("testing")
            .setAccessTokenValidityInMinutes(1)
            .setRefreshTokenValidityInHours(12)
            .build();

    InAppTokenAndCerts databaseRoleExtractorJwt = new InAppTokenAndCerts.Builder()
            .setPrivateKeyString(System.getenv("privateKey"))
            .setPublicKeyString(System.getenv("publicKey"))
            .usingSigningKeyStandard(SigningKeyStandards.PUBLIC_KEY)
            .setRoleExtractor(claims -> {
                if (!inMemDatabase.containsKey(claims.getSubject())) {
                    throw new RuntimeException("no user found");
                }
                Map<String, Object> user = inMemDatabase.get(claims.getSubject());
                System.out.println("database lookup for user roles");
                List<String> accessRoles = (List<String>) user.get("access_roles");
                Set<String> roles = new HashSet<>(accessRoles);
                return roles;})
            .setAudience("testing")
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

    @Override
    public InAppTokenAndCerts getInAppTokenAndCertsWithDatabaseRoleExtractor() {
        return databaseRoleExtractorJwt;
    }

    @Override
    public Map<String, Map<String, Object>> getInMemDatabase() {
        return inMemDatabase;
    }
}
