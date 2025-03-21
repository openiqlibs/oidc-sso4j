package com.sso4j.sso.auth0;

import com.sso4j.sso.abstracttests.AbstractSSOTokenAndCertsTest;
import com.sso4j.sso.defaults.auth.DefaultAuth0SSOTokenAndCerts;
import com.sso4j.sso.keycloak.AnotherKeycloakSSOAndCerts;
import com.sso4j.sso.keycloak.KeyCloakSSOAuth;
import com.sso4j.sso.keycloak.KeycloakSSOTest;
import com.sso4j.sso.keycloak.NotExistRealmSSOAndCerts;
import com.sso4j.sso.token.auth.AbstractSSOAuth;
import com.sso4j.sso.token.auth.AbstractSSOTokenAndCerts;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import java.io.IOException;


public class DefaultAuth0SSOAndCertsClassTest extends AbstractSSOTokenAndCertsTest {

    private AnotherKeycloakSSOAndCerts anotherKeycloakSSOAndCerts = new AnotherKeycloakSSOAndCerts();
    private DefaultAuth0SSOTokenAndCerts defaultAuth0SSOTokenAndCerts = new DefaultAuth0SSOTokenAndCerts(System.getenv("auth0_domain") + "/.well-known/jwks.json");

    private static String token;

    @BeforeClass
    public static void loadAuth0Response() throws IOException, InterruptedException {
        KeycloakSSOTest.loadSSOResponse();
        token = KeycloakSSOTest.ssoResponse.get("access_token").toString();
    }

    @Override
    @Test
    public void testGetListOfRolesObjectKeys() {
        Assert.assertNotNull(getSsoTokenAndCerts().getListOfRolesObjectKeys());
        Assert.assertEquals(1, getSsoTokenAndCerts().getListOfRolesObjectKeys().size());
    }

    @Override
    protected AbstractSSOTokenAndCerts getSsoTokenAndCerts() {
        return defaultAuth0SSOTokenAndCerts;
    }

    @Override
    protected AbstractSSOTokenAndCerts getNotExistRealmSSOAndCerts() {
        return new NotExistRealmSSOAndCerts();
    }

    @Override
    protected AbstractSSOTokenAndCerts getAnotherKeycloakSSOAndCerts() {
        return anotherKeycloakSSOAndCerts;
    }

    @Override
    protected AbstractSSOAuth getSSOAuth() {
        return new KeyCloakSSOAuth(anotherKeycloakSSOAndCerts);
    }

    @Override
    protected String token() {
        return token;
    }
}
