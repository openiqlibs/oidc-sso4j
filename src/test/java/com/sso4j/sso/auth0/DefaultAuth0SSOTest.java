package com.sso4j.sso.auth0;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sso4j.sso.abstracttests.AbstractSSOTest;
import com.sso4j.sso.defaults.auth.DefaultAuth0SSOTokenAndCerts;
import com.sso4j.sso.keycloak.KeycloakSSOTest;
import com.sso4j.sso.token.auth.AbstractSSOAuth;
import com.sso4j.sso.token.auth.AbstractSSOTokenAndCerts;
import org.junit.Assert;
import org.junit.BeforeClass;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class DefaultAuth0SSOTest extends AbstractSSOTest {

    DefaultAuth0SSOTokenAndCerts defaultAuth0SSOTokenAndCerts = new DefaultAuth0SSOTokenAndCerts(System.getenv("auth0_domain") + "/.well-known/jwks.json");

    public static Map<String, Object> auth0ssoResponse = new HashMap<>();

    private static Map<String, Object> getSSOAuthResponse(String url) throws IOException, InterruptedException {
        Map<String, String> requestMap = new HashMap<>();
        requestMap.put("grant_type", System.getenv("grant_type"));
        requestMap.put("client_id", System.getenv("client_id"));
        requestMap.put("client_secret", System.getenv("client_secret"));
        requestMap.put("audience", System.getenv("audience"));

        ObjectMapper objectMapper = new ObjectMapper();
        String jsonString = objectMapper.writeValueAsString(requestMap);
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonString))
                .build();
        HttpResponse<String> response;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
            String responseBody = response.body();
            if (response.statusCode() != 200) {
                throw new InterruptedException("responded with error code other than 200 " + responseBody);
            }
            return objectMapper.readValue(responseBody, new TypeReference<>() {
            });
        } catch (Exception e) {
            throw e;
        }
    }


    @BeforeClass
    public static void setup() throws IOException, InterruptedException {
        System.out.println("getting auth0 sso tokens..");
        auth0ssoResponse.putAll(getSSOAuthResponse(System.getenv("auth0_domain") + "/oauth/token"));
        KeycloakSSOTest.loadSSOResponse();
    }

    @Override
    protected AbstractSSOTokenAndCerts getSsoTokenAndCerts() {
        return defaultAuth0SSOTokenAndCerts;
    }

    @Override
    protected AbstractSSOAuth getSSOAuth() {
        return new Auth0SSOAuth(defaultAuth0SSOTokenAndCerts);
    }

    @Override
    protected String getToken() {
        return auth0ssoResponse.get("access_token").toString();
    }

    @Override
    protected String getDiffKidToken() {
        return KeycloakSSOTest.ssoResponse.get("access_token").toString();
    }

    @Override
    protected String getEmptyKidToken() {
        return "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE3NDIyODk5NjYsImV4cCI6MTc3MzgyNTk2NiwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.QoM49yoVbAhcIjoP5j25HOG8cBR_FWiRiAuPyO7re5o";
    }

    @Override
    protected String getTestKid() throws IOException {
        String token = auth0ssoResponse.get("access_token").toString();
        return getSSOAuth().getKid(getSSOAuth().getHeaders(token));
    }

    @Override
    public void testGetIssuer() throws IOException {
        Map<String, Object> payload = getSSOAuth().getPayload(getToken());
        String issuer = getSSOAuth().getIssuer(payload);
        org.junit.Assert.assertNotNull(issuer);
        Assert.assertEquals(System.getenv("auth0_issuer"), issuer);
    }

    @Override
    public void testKeyCloakSSOFlow() {
        Set<String> roles = null;
        try {
            roles = getSSOAuth().verifyAndExtractRoles(getToken());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        Assert.assertEquals(4, roles.size());
    }
}
