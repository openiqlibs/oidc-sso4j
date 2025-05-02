package io.github.openiqlibs.abstracttests;

import io.github.openiqlibs.models.CertConfigurations;
import io.github.openiqlibs.models.JwtCerts;
import io.github.openiqlibs.token.auth.AbstractSSOTokenAndCerts;
import io.jsonwebtoken.Claims;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

public class SSOTokenAndCertsMethodTest extends AbstractSSOTokenAndCerts {

    private JwtCerts withWrongAlg;
    private JwtCerts withWrongModAndExp;

    @Before
    public void setupMaps() {
        System.out.println("setting maps..");
        Map<String, Object> keyObject = new HashMap<>();
        CertConfigurations certConfigurations = new CertConfigurations();
        certConfigurations.setKty("NA");
        certConfigurations.setKid("76767676");

        Map<String, Object> keyObject2 = new HashMap<>();
        CertConfigurations certConfigurations2 = new CertConfigurations();
        certConfigurations2.setKty("RSA");
        certConfigurations2.setKid("76767676");
        certConfigurations2.setN(Base64.getEncoder().encodeToString(new BigInteger("12345").toByteArray()));
        certConfigurations2.setE(Base64.getEncoder().encodeToString(new BigInteger("6767674").toByteArray()));

        JwtCerts jwtCerts = new JwtCerts();
        JwtCerts jwtCerts2 = new JwtCerts();
        jwtCerts.setKeys(List.of(certConfigurations));
        jwtCerts2.setKeys(List.of(certConfigurations2));

        withWrongAlg = jwtCerts;
        withWrongModAndExp = jwtCerts2;
    }

    @Override
    public String getSSO_JWKsUrl() {
        return "http://localhost:8080/realms/testing/protocol/openid-connect/certs";
    }

    @Override
    public Set<String> getSetOfRolesObjectKeys() {
        return Set.of("realm_access");
    }

    @Override
    protected Set<String> extractRoles(Claims claims) {
        Set<String> roles = new HashSet<>();
        for (String key : getSetOfRolesObjectKeys()) {
            if (claims.containsKey(key)) {
                Map<String, Object> keyObj = (Map<String, Object>) claims.get(key);
                roles.addAll((Collection<String>) keyObj.get("roles"));
            } else {
                System.out.println("no roles present with key " + key);
            }
        }
        return roles;
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
