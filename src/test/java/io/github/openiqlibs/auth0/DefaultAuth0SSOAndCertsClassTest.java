package io.github.openiqlibs.auth0;

import io.github.openiqlibs.abstracttests.AbstractSSOTokenAndCertsTest;
import io.github.openiqlibs.keycloak.AnotherKeycloakSSOAndCerts;
import io.github.openiqlibs.keycloak.KeyCloakSSOAuth;
import io.github.openiqlibs.keycloak.KeycloakSSOTest;
import io.github.openiqlibs.keycloak.NotExistRealmSSOAndCerts;
import io.github.openiqlibs.token.auth.AbstractSSOAuth;
import io.github.openiqlibs.token.auth.AbstractSSOTokenAndCerts;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import java.io.IOException;


public class DefaultAuth0SSOAndCertsClassTest extends AbstractSSOTokenAndCertsTest {

    private AnotherKeycloakSSOAndCerts anotherKeycloakSSOAndCerts = new AnotherKeycloakSSOAndCerts();
    private Auth0SSOTokenAndCerts auth0SSOTokenAndCerts = new Auth0SSOTokenAndCerts();

    private static String token;

    @BeforeClass
    public static void loadAuth0Response() throws IOException, InterruptedException {
        KeycloakSSOTest.loadSSOResponse();
        token = KeycloakSSOTest.ssoResponse.get("access_token").toString();
    }

    @Override
    @Test
    public void testGetListOfRolesObjectKeys() {
        Assert.assertNotNull(getSsoTokenAndCerts().getSetOfRolesObjectKeys());
        Assert.assertEquals(1, getSsoTokenAndCerts().getSetOfRolesObjectKeys().size());
    }

    @Override
    protected AbstractSSOTokenAndCerts getSsoTokenAndCerts() {
        return auth0SSOTokenAndCerts;
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
