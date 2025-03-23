package com.sso4j.sso.abstracttests;

import com.sso4j.sso.token.auth.AbstractSSOAuth;
import com.sso4j.sso.token.auth.AbstractSSOTokenAndCerts;
import org.junit.Assert;
import org.junit.Test;

import java.util.Set;

public abstract class AbstractSSOTokenAndCertsTest {

    protected abstract AbstractSSOTokenAndCerts getSsoTokenAndCerts();

    protected abstract AbstractSSOTokenAndCerts getNotExistRealmSSOAndCerts();

    protected abstract AbstractSSOTokenAndCerts getAnotherKeycloakSSOAndCerts();

    protected abstract AbstractSSOAuth getSSOAuth();

    protected abstract String token();

    @Test
    public void testGetJwksUrl() {
        Assert.assertNotNull(getSsoTokenAndCerts().getSSO_JWKsUrl());
        Assert.assertNotEquals("", getSsoTokenAndCerts().getSSO_JWKsUrl());
    }

    @Test
    public void testGetListOfRolesObjectKeys() {
        Assert.assertNotNull(getSsoTokenAndCerts().getSetOfRolesObjectKeys());
        Assert.assertEquals(2, getSsoTokenAndCerts().getSetOfRolesObjectKeys().size());
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
