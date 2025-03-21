package com.sso4j.sso.abstracttests;

import com.sso4j.sso.token.auth.AbstractSSOAuth;
import com.sso4j.sso.token.auth.SSOTokenAndCerts;
import org.junit.Assert;
import org.junit.Test;

import java.util.Set;

public abstract class AbstractSSOTokenAndCertsTest {

    protected abstract SSOTokenAndCerts getSsoTokenAndCerts();

    protected abstract SSOTokenAndCerts getNotExistRealmSSOAndCerts();

    protected abstract SSOTokenAndCerts getAnotherKeycloakSSOAndCerts();

    protected abstract AbstractSSOAuth getSSOAuth();

    protected abstract String token();
    
    protected abstract String getSSOUrl();

    protected abstract Set<String> getListOfObjectKeys();

    @Test
    public void testGetJwksUrl() {
        Assert.assertNotNull(getSSOUrl());
        Assert.assertNotEquals("", getSSOUrl());
    }

    @Test
    public void testGetListOfRolesObjectKeys() {
        Assert.assertNotNull(getListOfObjectKeys());
        Assert.assertEquals(2, getListOfObjectKeys().size());
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
