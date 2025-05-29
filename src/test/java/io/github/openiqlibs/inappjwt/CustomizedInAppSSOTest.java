package io.github.openiqlibs.inappjwt;

import io.github.openiqlibs.enums.SigningKeyStandards;
import io.github.openiqlibs.token.auth.InAppTokenAndCerts;
import org.junit.Assert;

import java.util.*;

public class CustomizedInAppSSOTest extends InAppJwtSSOTest{

    public Map<String, Map<String, Object>> inMemDatabase = new HashMap<>();

    InAppTokenAndCerts inAppTokenAndCerts = new InAppTokenAndCerts.Builder()
            .setPrivateKeyString(System.getenv("privateKey"))
            .setPublicKeyString(System.getenv("publicKey"))
            .usingSigningKeyStandard(SigningKeyStandards.PUBLIC_KEY)
            .setRoleExtractor(claims -> {Set<String> roles = new HashSet<>();
                if (claims.containsKey("app_access")) {
                    roles.addAll((Collection<String>) claims.get("app_access"));
                } else {
                    System.out.println("no 'roles' key present to extract roles from claims");
                }
                return roles;})
            .setAudience("testing")
            .setIssuer("testing")
            .setAccessTokenValidityInMinutes(10)
            .setRefreshTokenValidityInHours(12)
            .build();

    InAppTokenAndCerts inAppDiffTokenAndCerts = new InAppTokenAndCerts.Builder()
            .setPrivateKeyString(System.getenv("privateKey2"))
            .setPublicKeyString(System.getenv("publicKey2"))
            .usingSigningKeyStandard(SigningKeyStandards.PUBLIC_KEY)
            .setRoleExtractor(claims -> {Set<String> roles = new HashSet<>();
                if (claims.containsKey("app_access")) {
                    roles.addAll((Collection<String>) claims.get("app_access"));
                } else {
                    System.out.println("no 'roles' key present to extract roles from claims");
                }
                return roles;})
            .setIssuer("testing")
            .setAudience("testing")
            .setAccessTokenValidityInMinutes(10)
            .setRefreshTokenValidityInHours(12)
            .build();

    InAppTokenAndCerts toExpiredTokenAndCerts = new InAppTokenAndCerts.Builder()
            .setPrivateKeyString(System.getenv("privateKey"))
            .setPublicKeyString(System.getenv("publicKey"))
            .usingSigningKeyStandard(SigningKeyStandards.PUBLIC_KEY)
            .setRoleExtractor(claims -> {Set<String> roles = new HashSet<>();
                if (claims.containsKey("app_access")) {
                    roles.addAll((Collection<String>) claims.get("app_access"));
                } else {
                    System.out.println("no 'roles' key present to extract roles from claims");
                }
                return roles;})
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

    @Override
    public void testNormalExtractRoleFlowWithSecretKey() throws Exception {
        Map<String, Object> claims = Map.of("app_access", List.of("normal", "admin"));
        Map<String, String> tokenPair = getInAppTokenAndCertsWithSecretKey().generateTokenPair(claims, "testUser");
        Set<String> roles = inAppJwtSSO.verifyAndExtractRoles(tokenPair.get("accessToken"));
        Assert.assertNotNull(roles);
        Assert.assertEquals(2, roles.size());
        Assert.assertTrue(roles.contains("normal") && roles.contains("admin"));
    }
}
