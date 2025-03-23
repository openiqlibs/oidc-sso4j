package io.github.openiqlibs.keycloak;

import io.github.openiqlibs.abstracttests.AbstractSSOTokenAndCertsTest;
import io.github.openiqlibs.token.auth.AbstractSSOAuth;
import io.github.openiqlibs.token.auth.AbstractSSOTokenAndCerts;
import org.junit.BeforeClass;

import java.io.IOException;

public class KeycloakSSOTokenAndCertsTest extends AbstractSSOTokenAndCertsTest {

    private AnotherKeycloakSSOAndCerts anotherKeycloakSSOAndCerts = new AnotherKeycloakSSOAndCerts();
    private KeyCloakSSOAndCerts keyCloakSSOAndCerts = new KeyCloakSSOAndCerts();

    private static String token;

    @BeforeClass
    public static void loadSSOToken() throws InterruptedException, IOException {
        KeycloakSSOTest.loadSSOResponse();
        token = KeycloakSSOTest.ssoResponse.get("access_token").toString();
    }

    @Override
    protected AbstractSSOTokenAndCerts getSsoTokenAndCerts() {
        return keyCloakSSOAndCerts;
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
