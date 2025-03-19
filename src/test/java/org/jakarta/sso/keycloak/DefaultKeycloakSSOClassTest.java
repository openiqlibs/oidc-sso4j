package org.jakarta.sso.keycloak;

import org.jakarta.sso.abstracttests.AbstractSSOTokenAndCertsTest;
import org.jakarta.sso.enums.KeycloakScopes;
import org.jakarta.sso.keycloak.auth.DefaultKeycloakSSOTokenAndCerts;
import org.jakarta.sso.token.auth.AbstractSSOAuth;
import org.jakarta.sso.token.auth.SSOTokenAndCerts;
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
