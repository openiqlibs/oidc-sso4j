package io.github.openiqlibs.keycloak;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.openiqlibs.abstracttests.AbstractSSOTest;
import io.github.openiqlibs.token.auth.AbstractSSOAuth;
import io.github.openiqlibs.token.auth.AbstractSSOTokenAndCerts;
import org.junit.BeforeClass;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class KeycloakSSOTest extends AbstractSSOTest {

    private KeyCloakSSOAndCerts keyCloakSSOAndCerts = new KeyCloakSSOAndCerts();

    public static Map<String, Object> ssoResponse = new HashMap<>();
    public static Map<String, Object> ssoResponse2 = new HashMap<>();

    private static Map<String, Object> getSSOAuthResponse(String url) throws IOException, InterruptedException {
        String formEncoded = "client_id=test-app&username=test-user&password=12345&grant_type=password";
        ObjectMapper objectMapper = new ObjectMapper();
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formEncoded, StandardCharsets.UTF_8))
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
    public static void loadSSOResponse() throws IOException, InterruptedException {
        System.out.println("getting sso tokens..");
        Map<String, Object> resp = getSSOAuthResponse("http://localhost:8080/realms/testing/protocol/openid-connect/token");
        Map<String, Object> resp2 = getSSOAuthResponse("http://localhost:8080/realms/testing-2/protocol/openid-connect/token");

        ssoResponse.putAll(resp);
        ssoResponse2.putAll(resp2);
    }

    @Override
    protected AbstractSSOTokenAndCerts getSsoTokenAndCerts() {
        return keyCloakSSOAndCerts;
    }

    @Override
    protected AbstractSSOAuth getSSOAuth() {
        return new KeyCloakSSOAuth(keyCloakSSOAndCerts);
    }

    @Override
    protected String getToken() {
        return ssoResponse.get("access_token").toString();
    }

    @Override
    protected String getDiffKidToken() {
        return ssoResponse2.get("access_token").toString();
    }

    @Override
    protected String getEmptyKidToken() {
        return "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE3NDIyODk5NjYsImV4cCI6MTc3MzgyNTk2NiwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.QoM49yoVbAhcIjoP5j25HOG8cBR_FWiRiAuPyO7re5o";
    }

    @Override
    protected String getTestKid() throws IOException {
        String token = ssoResponse.get("access_token").toString();
        return getSSOAuth().getKid(getSSOAuth().getHeaders(token));
    }
}
