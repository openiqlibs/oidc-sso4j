package com.sso4j.sso.keycloak;

import com.sso4j.sso.abstracttests.AbstractSSOTokenAndCertsTest;
import com.sso4j.sso.enums.KeycloakScopes;
import com.sso4j.sso.defaults.auth.DefaultKeycloakSSOTokenAndCerts;
import com.sso4j.sso.token.auth.AbstractSSOAuth;
import com.sso4j.sso.token.auth.SSOTokenAndCerts;
import org.junit.BeforeClass;

import java.io.IOException;
import java.util.Set;

public class DefaultKeycloakSSOClassTest extends AbstractSSOTokenAndCertsTest {

    private AnotherKeycloakSSOAndCerts anotherKeycloakSSOAndCerts = new AnotherKeycloakSSOAndCerts();
    private DefaultKeycloakSSOTokenAndCerts defaultKeycloakSSOTokenAndCerts = new DefaultKeycloakSSOTokenAndCerts("http://localhost:8080/realms/testing/protocol/openid-connect/certs");

    private static String token;

    @BeforeClass
    public static void loadSSOToken() throws InterruptedException, IOException {
        KeycloakSSOTest.loadSSOResponse();
        token = KeycloakSSOTest.ssoResponse.get("access_token").toString();
    }

    @Override
    protected SSOTokenAndCerts getSsoTokenAndCerts() {
        return defaultKeycloakSSOTokenAndCerts;
    }

    @Override
    protected SSOTokenAndCerts getNotExistRealmSSOAndCerts() {
        return new NotExistRealmSSOAndCerts();
    }

    @Override
    protected SSOTokenAndCerts getAnotherKeycloakSSOAndCerts() {
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

    @Override
    protected String getSSOUrl() {
        return "http://localhost:8080/realms/testing/protocol/openid-connect/certs";
    }

    @Override
    protected Set<String> getListOfObjectKeys() {
        return Set.of(KeycloakScopes.REALM_ACCESS.getValue(), KeycloakScopes.RESOURCE_ACCESS.getValue());
    }
}
