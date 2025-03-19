package org.jakarta.sso.abstracttests;

import org.jakarta.sso.token.auth.SSOTokenAndCerts;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

public class SSOTokenAndCertsMethodTest extends SSOTokenAndCerts {

    private Map<String, Object> withWrongAlg = new HashMap<>();
    private Map<String, Object> withWrongModAndExp =new HashMap<>();

    @Before
    public void setupMaps() {
        System.out.println("setting maps..");
        Map<String, Object> keyObject = new HashMap<>();
        keyObject.put("kty", "NA");
        keyObject.put("kid", "76767676");

        Map<String, Object> keyObject2 = new HashMap<>();
        keyObject2.put("kty", "RSA");
        keyObject2.put("kid", "76767676");
        keyObject2.put("n", Base64.getEncoder().encodeToString(new BigInteger("12345").toByteArray()));
        keyObject2.put("e", Base64.getEncoder().encodeToString(new BigInteger("6767674").toByteArray()));
        withWrongAlg.put("keys", List.of(keyObject));
        withWrongModAndExp.put("keys", List.of(keyObject2));
    }

    @Override
    protected String getSSO_JWKsUrl() {
        return "http://localhost:8080/realms/testing/protocol/openid-connect/certs";
    }

    @Override
    protected Set<String> getListOfRolesObjectKeys() {
        return Set.of("realm_access");
    }

    @Test
    public void testGetPublicKeysWithException() {
        boolean exceptionOccur;
        try {
            getPublicKeys(withWrongAlg);
            exceptionOccur = false;
        } catch (Exception e) {
            exceptionOccur = true;
        }
        Assert.assertTrue(exceptionOccur);
    }

    @Test
    public void testGetPublicKeysWithInvalidKeySpecException() {
        Assert.assertThrows(InvalidKeySpecException.class, () -> getPublicKeys(withWrongModAndExp));
    }

    @Test
    public void testGetPublicKeysWithNoSuchAlgorithmException() {
        Assert.assertThrows(NoSuchAlgorithmException.class, () -> getPublicKeys(withWrongAlg));
    }
}
