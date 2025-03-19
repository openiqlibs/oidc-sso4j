package org.jakarta.sso.inappjwt;

import org.jakarta.sso.enums.SigningKeyStandards;
import org.jakarta.sso.token.auth.InAppTokenAndCerts;
import org.junit.Assert;
import org.junit.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

public class InAppJwtSSOTest {

    InAppTokenAndCerts inAppTokenAndCertsWithSecretKey = new InAppTokenAndCerts.Builder()
            .setSecretValue("nlcksncjdksjiefowhuhdiuwgdyfewghcdfcuwgdikqjdknjwchkuehwyuvxctywev")
            .usingSigningKeyStandard(SigningKeyStandards.SECRET_KEY)
            .setIssuer("testing")
            .setAccessTokenValidityInMinutes(10)
            .setRefreshTokenValidityInHours(12)
            .build();

    InAppJwtSSO inAppJwtSSO = new InAppJwtSSO();

    @Test
    public void testNormalExtractRoleFlow() throws Exception {
        Map<String, Object> claims = Map.of("roles", List.of("normal", "admin"));
        Map<String, String> tokenPair = inAppTokenAndCertsWithSecretKey.generateTokenPair(claims, "testUser");
        Set<String> roles = inAppTokenAndCertsWithSecretKey.getRolesOfToken(tokenPair.get("accessToken"));
        Assert.assertNotNull(roles);
        Assert.assertEquals(2, roles.size());
        Assert.assertTrue(roles.contains("normal") && roles.contains("admin"));
    }



}
