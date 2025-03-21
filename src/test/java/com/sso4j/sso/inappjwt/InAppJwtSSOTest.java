package com.sso4j.sso.inappjwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import com.sso4j.sso.enums.SigningKeyStandards;
import com.sso4j.sso.token.auth.InAppTokenAndCerts;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

public abstract class InAppJwtSSOTest {

    public abstract InAppTokenAndCerts getInAppTokenAndCertsWithSecretKey();

    public abstract InAppTokenAndCerts getToTestExpiredToken();

    public abstract InAppTokenAndCerts getInAppTokenAndCertsWithDiffSecretKey();

    InAppJwtSSO inAppJwtSSO;
    InAppJwtSSO expiredInAppJwtSSO;

    @Before
    public void setupObjs() {
        inAppJwtSSO = new InAppJwtSSO(getInAppTokenAndCertsWithSecretKey());
        expiredInAppJwtSSO = new InAppJwtSSO(getToTestExpiredToken());
    }

    @Test
    public void testNormalExtractRoleFlowWithSecretKey() throws Exception {
        Map<String, Object> claims = Map.of("roles", List.of("normal", "admin"));
        Map<String, String> tokenPair = getInAppTokenAndCertsWithSecretKey().generateTokenPair(claims, "testUser");
        Set<String> roles = inAppJwtSSO.verifyAndExtractRoles(tokenPair.get("accessToken"));
        Assert.assertNotNull(roles);
        Assert.assertEquals(2, roles.size());
        Assert.assertTrue(roles.contains("normal") && roles.contains("admin"));
    }

    @Test
    public void testNormalExtractRoleErrorFlowWithSecretKey() throws Exception {
        Map<String, Object> claims = Map.of("roles", List.of("normal", "admin"));
        Map<String, String> tokenPair = getInAppTokenAndCertsWithDiffSecretKey().generateTokenPair(claims, "testUser");
        Assert.assertThrows(SignatureException.class, () -> inAppJwtSSO.verifyAndExtractRoles(tokenPair.get("accessToken")));
    }

    @Test
    public void testIsNullOrIsEmptyOrIsBlank() {
        String nullString = null;
        String emptyString = "";
        String blankString = " ";

        Assert.assertTrue(InAppTokenAndCerts.isNullOrEmptyOrBlank(nullString));
        Assert.assertTrue(InAppTokenAndCerts.isNullOrEmptyOrBlank(emptyString));
        Assert.assertTrue(InAppTokenAndCerts.isNullOrEmptyOrBlank(blankString));
    }

    @Test
    public void testEmptyRolesToken() throws Exception {
        Map<String, Object> claims = Map.of();
        Map<String, String> tokenPair = getInAppTokenAndCertsWithSecretKey().generateTokenPair(claims, "testUser");
        Set<String> roles = inAppJwtSSO.verifyAndExtractRoles(tokenPair.get("accessToken"));
        Assert.assertNotNull(roles);
        Assert.assertEquals(0, roles.size());
    }

    @Test
    public void testExpiredTokenFlow() throws Exception {
        Map<String, Object> claims = Map.of("roles", List.of("normal", "admin"));
        Map<String, String> tokenPair = getToTestExpiredToken().generateTokenPair(claims, "testUser");
        System.out.println("waiting for 1 minute to test expiredToken");
        Thread.sleep(1000 * 61);
        Assert.assertThrows(ExpiredJwtException.class, () -> expiredInAppJwtSSO.verifyAndExtractRoles(tokenPair.get("accessToken")));
    }

    @Test
    public void testValidateFieldKeyToUse() {
        try {
            new InAppTokenAndCerts.Builder()
                    .setSecretValue("nlcksncjdksjiefowhuhdiuwgdyfewghcdfcuwgdikqjdknjwchkuehwyuvxctywev")
                    .setIssuer("testing")
                    .setAccessTokenValidityInMinutes(10)
                    .setRefreshTokenValidityInHours(12)
                    .build();
        } catch (Exception e) {
            boolean isRunTimeException = e instanceof RuntimeException;
            Assert.assertTrue(isRunTimeException);
            Assert.assertEquals("initialize signing key standard using signing key standard enum", e.getMessage());
        }
    }

    @Test
    public void testValidateFieldSecretString() {
        try {
            new InAppTokenAndCerts.Builder()
                    .usingSigningKeyStandard(SigningKeyStandards.SECRET_KEY)
                    .setIssuer("testing")
                    .setAccessTokenValidityInMinutes(10)
                    .setRefreshTokenValidityInHours(12)
                    .build();
        } catch (Exception e) {
            boolean isRunTimeException = e instanceof RuntimeException;
            Assert.assertTrue(isRunTimeException);
            Assert.assertEquals("secret cannot be null or empty", e.getMessage());
        }
    }

    @Test
    public void testValidateFieldIssuer() {
        try {
            new InAppTokenAndCerts.Builder()
                    .setSecretValue("nlcksncjdksjiefowhuhdiuwgdyfewghcdfcuwgdikqjdknjwchkuehwyuvxctywev")
                    .usingSigningKeyStandard(SigningKeyStandards.SECRET_KEY)
                    .setAccessTokenValidityInMinutes(10)
                    .setRefreshTokenValidityInHours(12)
                    .build();
        } catch (Exception e) {
            boolean isRunTimeException = e instanceof RuntimeException;
            Assert.assertTrue(isRunTimeException);
            Assert.assertEquals("issuer cannot be null or empty", e.getMessage());
        }
    }

    @Test
    public void testValidateFieldAccessTokenValidity() {
        try {
            new InAppTokenAndCerts.Builder()
                    .setSecretValue("nlcksncjdksjiefowhuhdiuwgdyfewghcdfcuwgdikqjdknjwchkuehwyuvxctywev")
                    .usingSigningKeyStandard(SigningKeyStandards.SECRET_KEY)
                    .setIssuer("testing")
                    .setRefreshTokenValidityInHours(12)
                    .build();
        } catch (Exception e) {
            boolean isRunTimeException = e instanceof RuntimeException;
            Assert.assertTrue(isRunTimeException);
            Assert.assertEquals("initialize access token validity and it should not be greater than 15 minutes", e.getMessage());
        }

        try {
            new InAppTokenAndCerts.Builder()
                    .setSecretValue("nlcksncjdksjiefowhuhdiuwgdyfewghcdfcuwgdikqjdknjwchkuehwyuvxctywev")
                    .usingSigningKeyStandard(SigningKeyStandards.SECRET_KEY)
                    .setIssuer("testing")
                    .setAccessTokenValidityInMinutes(20)
                    .setRefreshTokenValidityInHours(12)
                    .build();
        } catch (Exception e) {
            boolean isRunTimeException = e instanceof RuntimeException;
            Assert.assertTrue(isRunTimeException);
            Assert.assertEquals("initialize access token validity and it should not be greater than 15 minutes", e.getMessage());
        }
    }

    @Test
    public void testValidateFieldRefreshTokenValidity() {
        try {
            new InAppTokenAndCerts.Builder()
                    .setSecretValue("nlcksncjdksjiefowhuhdiuwgdyfewghcdfcuwgdikqjdknjwchkuehwyuvxctywev")
                    .usingSigningKeyStandard(SigningKeyStandards.SECRET_KEY)
                    .setIssuer("testing")
                    .setAccessTokenValidityInMinutes(10)
                    .build();
        } catch (Exception e) {
            boolean isRunTimeException = e instanceof RuntimeException;
            Assert.assertTrue(isRunTimeException);
            Assert.assertEquals("initialize access token validity and it should not be greater than 24 hours", e.getMessage());
        }

        try {
            new InAppTokenAndCerts.Builder()
                    .setSecretValue("nlcksncjdksjiefowhuhdiuwgdyfewghcdfcuwgdikqjdknjwchkuehwyuvxctywev")
                    .usingSigningKeyStandard(SigningKeyStandards.SECRET_KEY)
                    .setIssuer("testing")
                    .setAccessTokenValidityInMinutes(10)
                    .setRefreshTokenValidityInHours(30)
                    .build();
        } catch (Exception e) {
            boolean isRunTimeException = e instanceof RuntimeException;
            Assert.assertTrue(isRunTimeException);
            Assert.assertEquals("initialize access token validity and it should not be greater than 24 hours", e.getMessage());
        }
    }

    @Test
    public void testValidateFieldPrivateAndPublicString() {
        try {
            new InAppTokenAndCerts.Builder()
                    .setPrivateKeyString("jdkjdkshdkjshdkshdk")
                    .usingSigningKeyStandard(SigningKeyStandards.PUBLIC_KEY)
                    .setAccessTokenValidityInMinutes(10)
                    .setRefreshTokenValidityInHours(12)
                    .build();
        } catch (Exception e) {
            boolean isRunTimeException = e instanceof RuntimeException;
            Assert.assertTrue(isRunTimeException);
            Assert.assertEquals("public key string cannot be null or empty", e.getMessage());
        }

        try {
            new InAppTokenAndCerts.Builder()
                    .setPublicKeyString("jdkjdkshdkjshdkshdk")
                    .usingSigningKeyStandard(SigningKeyStandards.PUBLIC_KEY)
                    .setAccessTokenValidityInMinutes(10)
                    .setRefreshTokenValidityInHours(12)
                    .build();
        } catch (Exception e) {
            boolean isRunTimeException = e instanceof RuntimeException;
            Assert.assertTrue(isRunTimeException);
            Assert.assertEquals("private key string cannot be null or empty", e.getMessage());
        }
    }

}
