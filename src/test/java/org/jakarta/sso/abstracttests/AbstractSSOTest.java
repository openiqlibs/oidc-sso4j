package org.jakarta.sso.abstracttests;

import io.jsonwebtoken.ExpiredJwtException;
import org.jakarta.sso.token.auth.AbstractSSOAuth;
import org.jakarta.sso.token.auth.SSOTokenAndCerts;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.Set;

public abstract class AbstractSSOTest {

    protected abstract SSOTokenAndCerts getSsoTokenAndCerts();

    protected abstract AbstractSSOAuth getSSOAuth();

    protected abstract String getToken();

    protected abstract String getDiffKidToken();

    protected abstract String getEmptyKidToken();

    protected abstract String getTestKid() throws IOException;

    @Before
    public void setupObjs() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InterruptedException {
        System.out.println("setting up objects...");
        this.getSsoTokenAndCerts().downloadAndStorePublicKeys();
    }

    @Test
    public void testKeyCloakSSOFlow() {
        Set<String> roles = null;
        try {
            roles = getSSOAuth().verifyAndExtractRoles(getToken());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        Assert.assertEquals(3, roles.size());
    }

    @Test
    public void testKeycloakSSOExpiredTokenFlow() {
        try {
            getSSOAuth().verifyAndExtractRoles(getToken());
        } catch (Exception e) {
            boolean flag = e instanceof ExpiredJwtException;
            Assert.assertTrue(flag);
            Assert.assertTrue(e.getMessage().contains("JWT expired"));
        }
    }

    @Test
    public void testKeycloakSSONullSignatureFlow() {
        try {
            getSSOAuth().verifyAndExtractRoles(getDiffKidToken());
        } catch (Exception e) {
            boolean flag = e instanceof IllegalArgumentException;
            Assert.assertTrue(flag);
            Assert.assertEquals("signature verification key cannot be null.", e.getMessage());
        }
    }

    @Test
    public void testGetHeaders() throws IOException {
        Map<String, Object> headers = getSSOAuth().getHeaders(getToken());
        org.junit.Assert.assertNotNull(headers);
        org.junit.Assert.assertFalse(headers.isEmpty());
    }

    @Test
    public void testGetPayload() throws IOException {
        Map<String, Object> payload = getSSOAuth().getPayload(getToken());
        Assert.assertNotNull(payload);
        Assert.assertFalse(payload.isEmpty());
    }

    @Test
    public void testGetIssuer() throws IOException {
        Map<String, Object> payload = getSSOAuth().getPayload(getToken());
        String issuer = getSSOAuth().getIssuer(payload);
        org.junit.Assert.assertNotNull(issuer);
        Assert.assertEquals("http://localhost:8080/realms/testing", issuer);
    }

    @Test
    public void testGetKid() throws IOException {
        Map<String, Object> headers = getSSOAuth().getHeaders(getToken());
        String kid = getSSOAuth().getKid(headers);
        org.junit.Assert.assertNotNull(kid);
        Assert.assertEquals(getTestKid(), kid);
    }

    @Test
    public void testGetKidEmpty() throws IOException {
        Map<String, Object> headers = getSSOAuth().getHeaders(getEmptyKidToken());
        String kid = getSSOAuth().getKid(headers);
        org.junit.Assert.assertNotNull(kid);
        Assert.assertEquals("", kid);
    }
}
