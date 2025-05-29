package io.github.openiqlibs.inappjwt;

import io.github.openiqlibs.enums.SigningKeyStandards;
import io.github.openiqlibs.token.auth.InAppTokenAndCerts;

import java.util.*;

public class SecretKeyInAppJwtSSOTest extends InAppJwtSSOTest{

    public Map<String, Map<String, Object>> inMemDatabase = new HashMap<>();

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

    InAppTokenAndCerts databaseRoleExtractorJwt = new InAppTokenAndCerts.Builder()
            .setSecretValue("nlcksncjdksjiefowhuhdkiwgdyfewghcdfcuwgdikqjdknjwchkuehwyuvxctywev")
            .usingSigningKeyStandard(SigningKeyStandards.SECRET_KEY)
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

    @Override
    public InAppTokenAndCerts getInAppTokenAndCertsWithDatabaseRoleExtractor() {
        return databaseRoleExtractorJwt;
    }

    @Override
    public Map<String, Map<String, Object>> getInMemDatabase() {
        return inMemDatabase;
    }
}
