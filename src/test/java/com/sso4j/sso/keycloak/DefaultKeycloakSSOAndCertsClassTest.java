package com.sso4j.sso.keycloak;

import com.sso4j.sso.abstracttests.AbstractSSOTokenAndCertsTest;
import com.sso4j.sso.defaults.auth.DefaultKeycloakSSOTokenAndCerts;
import com.sso4j.sso.token.auth.AbstractSSOAuth;
import com.sso4j.sso.token.auth.AbstractSSOTokenAndCerts;
import org.junit.BeforeClass;

import java.io.IOException;

public class DefaultKeycloakSSOAndCertsClassTest extends AbstractSSOTokenAndCertsTest {

    private AnotherKeycloakSSOAndCerts anotherKeycloakSSOAndCerts = new AnotherKeycloakSSOAndCerts();
    private DefaultKeycloakSSOTokenAndCerts defaultKeycloakSSOTokenAndCerts = new DefaultKeycloakSSOTokenAndCerts("http://localhost:8080/realms/testing/protocol/openid-connect/certs");

    private static String token;

    @BeforeClass
    public static void loadSSOToken() throws InterruptedException, IOException {
        KeycloakSSOTest.loadSSOResponse();
        token = KeycloakSSOTest.ssoResponse.get("access_token").toString();
    }

    @Override
    protected AbstractSSOTokenAndCerts getSsoTokenAndCerts() {
        return defaultKeycloakSSOTokenAndCerts;
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
