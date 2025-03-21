package com.sso4j.sso.keycloak;

import com.sso4j.sso.abstracttests.AbstractSSOTest;
import com.sso4j.sso.defaults.auth.DefaultKeycloakSSOTokenAndCerts;
import com.sso4j.sso.token.auth.AbstractSSOAuth;
import com.sso4j.sso.token.auth.AbstractSSOTokenAndCerts;
import org.junit.Assert;
import org.junit.BeforeClass;

import java.io.IOException;
import java.util.Set;

public class DefaultKeycloakSSOTest extends AbstractSSOTest {

    DefaultKeycloakSSOTokenAndCerts defaultKeycloakSSOTokenAndCerts = new DefaultKeycloakSSOTokenAndCerts("http://localhost:8080/realms/testing/protocol/openid-connect/certs");

    @BeforeClass
    public static void setup() throws IOException, InterruptedException {
        System.out.println("getting keycloak sso tokens..");
        KeycloakSSOTest.loadSSOResponse();
    }

    @Override
    protected AbstractSSOTokenAndCerts getSsoTokenAndCerts() {
        return defaultKeycloakSSOTokenAndCerts;
    }

    @Override
    protected AbstractSSOAuth getSSOAuth() {
        return new KeyCloakSSOAuth(defaultKeycloakSSOTokenAndCerts);
    }

    @Override
    protected String getToken() {
        return KeycloakSSOTest.ssoResponse.get("access_token").toString();
    }

    @Override
    protected String getDiffKidToken() {
        return KeycloakSSOTest.ssoResponse2.get("access_token").toString();
    }

    @Override
    protected String getEmptyKidToken() {
        return "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE3NDIyODk5NjYsImV4cCI6MTc3MzgyNTk2NiwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.QoM49yoVbAhcIjoP5j25HOG8cBR_FWiRiAuPyO7re5o";
    }

    @Override
    protected String getTestKid() throws IOException {
        String token = KeycloakSSOTest.ssoResponse.get("access_token").toString();
        return getSSOAuth().getKid(getSSOAuth().getHeaders(token));
    }

    @Override
    public void testKeyCloakSSOFlow() {
        Set<String> roles = null;
        try {
            roles = getSSOAuth().verifyAndExtractRoles(getToken());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        Assert.assertEquals(6, roles.size());
    }
}
