package org.jakarta.sso.abstracttests;

import org.jakarta.sso.token.auth.AbstractSSOAuth;
import org.jakarta.sso.token.auth.SSOTokenAndCerts;
import org.junit.Assert;
import org.junit.Test;

import java.util.Set;

public abstract class AbstractSSOTokenAndCertsTest {

    protected abstract SSOTokenAndCerts getSsoTokenAndCerts();

    protected abstract SSOTokenAndCerts getNotExistRealmSSOAndCerts();

    protected abstract SSOTokenAndCerts getAnotherKeycloakSSOAndCerts();

    protected abstract AbstractSSOAuth getSSOAuth();

    protected abstract String token();

    @Test
    public void testGetJwksUrl() {
        Assert.assertNotNull(getSsoTokenAndCerts().getSSO_JWKsUrl());
        Assert.assertNotEquals("", getSsoTokenAndCerts().getSSO_JWKsUrl());
    }

    @Test
    public void testGetListOfRolesObjectKeys() {
        Assert.assertNotNull(getSsoTokenAndCerts().getListOfRolesObjectKeys());
        Assert.assertEquals(1, getSsoTokenAndCerts().getListOfRolesObjectKeys().size());
    }

    @Test
    public void testGetSSOCertsDownloadAndLoadPublicKeys() {
        boolean exceptionFlag;
        try {
            getSsoTokenAndCerts().downloadAndStorePublicKeys();
            exceptionFlag = false;
        } catch (Exception e) {
            exceptionFlag = true;
        }
        Assert.assertFalse(exceptionFlag);
    }

    @Test
    public void testGetSSOCertsDownloadException() {
        boolean exceptionFlag;
        try {
            getNotExistRealmSSOAndCerts().downloadAndStorePublicKeys();
            exceptionFlag = false;
        } catch (Exception e) {
            exceptionFlag = true;
        }
        Assert.assertTrue(exceptionFlag);
    }

    @Test
    public void testEmptyExtractRoles() throws Exception {
        String kid = getSSOAuth().getKid(getSSOAuth().getHeaders(token()));
        getAnotherKeycloakSSOAndCerts().downloadAndStorePublicKeys();
        Set<String> roles = getAnotherKeycloakSSOAndCerts().getRolesOfToken(token(), kid);
        Assert.assertNotNull(roles);
        Assert.assertEquals(0, roles.size());
    }
}
