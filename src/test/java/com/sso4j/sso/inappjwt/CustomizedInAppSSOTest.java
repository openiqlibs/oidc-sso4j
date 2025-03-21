package com.sso4j.sso.inappjwt;

import com.sso4j.sso.enums.SigningKeyStandards;
import com.sso4j.sso.token.auth.InAppTokenAndCerts;
import org.junit.Assert;

import java.util.*;

public class CustomizedInAppSSOTest extends InAppJwtSSOTest{

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
    public void testNormalExtractRoleFlowWithSecretKey() throws Exception {
        Map<String, Object> claims = Map.of("app_access", List.of("normal", "admin"));
        Map<String, String> tokenPair = getInAppTokenAndCertsWithSecretKey().generateTokenPair(claims, "testUser");
        Set<String> roles = inAppJwtSSO.verifyAndExtractRoles(tokenPair.get("accessToken"));
        Assert.assertNotNull(roles);
        Assert.assertEquals(2, roles.size());
        Assert.assertTrue(roles.contains("normal") && roles.contains("admin"));
    }
}
