package org.jakarta.sso.keycloak;

import io.jsonwebtoken.ExpiredJwtException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.Set;

public class KeycloakSSOTest {

    KeyCloakSSOAndCerts keyCloakSSOAndCerts;
    KeyCloakSSOAuth keyCloakSSOAuth;
    String token;

    @Before
    public void setupObjs() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InterruptedException {
        System.out.println("setting up objects...");
        keyCloakSSOAndCerts = new KeyCloakSSOAndCerts();
        keyCloakSSOAndCerts.downloadAndStorePublicKeys();
        keyCloakSSOAuth = new KeyCloakSSOAuth(keyCloakSSOAndCerts);
        token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzLVY4anZvX1FsUnNQMVdPUmFDd3B3YUgzOEpwN2l1SkFQeDlDLVJYSHpVIn0.eyJleHAiOjE3NDIyOTM2NDgsImlhdCI6MTc0MjI5MzM0OCwianRpIjoiOWU3OTgxNTctMGUyYS00NTQ5LWI3MTUtNjAwYjdlMzNhMjMxIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy90ZXN0aW5nIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6IjhhMjA3MWVjLWU2M2MtNGQ1Zi1hNmVhLTk2ZWQzNWY4MWVmNSIsInR5cCI6IkJlYXJlciIsImF6cCI6InRlc3QtYXBwIiwic2lkIjoiODE0NGU1ZjgtNjhiNS00OGExLWEyZGUtNTNmODU5MzNkYWQ2IiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyIvKiJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGVmYXVsdC1yb2xlcy10ZXN0aW5nIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwibmFtZSI6InMgcyIsInByZWZlcnJlZF91c2VybmFtZSI6InRlc3QtdXNlciIsImdpdmVuX25hbWUiOiJzIiwiZmFtaWx5X25hbWUiOiJzIiwiZW1haWwiOiJ3cUBqbWFpbC5jb20ifQ.AXOViLf7Bbu0uPW1GUoCa3znIpDWQabArcvRnOQ-vkymelzZrgkijjx7kOzB80ZECOsPqpw2biPscMmPaM988IzKCNtBN_pI-61G0oS5bYz8dtDqMSvcv8nalhA41NUaGImkMvs6byz5MC08qA4ryzid7T0k48l-GM4jpSchgrY2LEAoaFJlenf9eW3NInsWEnusIqfqpApf13peWZvcmHAzn1kGNiFMx3k12tcSuQIRztoWNPLC-bhByWmFDkx0gzRdBbd67H4InlqzhaMUaf3NtXaKEe__c9xST4cvWw3xA_wnrbOstMB-2Z5xwzoKf6Mi1tp5MVm4W-ec_UVTBw";
    }

    @Test
    public void testKeyCloakSSOFlow() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InterruptedException {
        Set<String> roles = null;
        try {
            roles = this.keyCloakSSOAuth.verifyAndExtractRoles(this.token);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        org.junit.Assert.assertEquals(3, roles.size());
    }

    @Test
    public void testKeycloakSSOExpiredTokenFlow() {
        try {
            this.keyCloakSSOAuth.verifyAndExtractRoles(this.token);
        } catch (Exception e) {
            boolean flag = e instanceof ExpiredJwtException;
            Assert.assertTrue(flag);
            Assert.assertTrue(e.getMessage().contains("JWT expired"));
        }
    }

    @Test
    public void testKeycloakSSONullSignatureFlow() {
        String diffKidToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJuYXYwRGpNNXg5eUloUE5SRHVrR0JqZ0tPZDczWnE5Mm9mNmVYUU02NUJrIn0.eyJleHAiOjE3NDIyOTM2OTMsImlhdCI6MTc0MjI5MzM5MywianRpIjoiMDMzZWNhYjItYjc5MC00ODdiLTg3NGUtZGUyODJkZTU1NWIwIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy90ZXN0aW5nLTIiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiOTI3MTIxMTYtZmZlZS00NTkwLThjZDEtOWNmNjBmNTljZmEyIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoidGVzdC1hcHAiLCJzaWQiOiJjYmZiMmYwMy04NjY2LTQ5ODQtYWVlYS1kYWZjZGI4ODYxMjQiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbIi8qIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsImRlZmF1bHQtcm9sZXMtdGVzdGluZy0yIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6InByb2ZpbGUgZW1haWwiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJzIHMiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ0ZXN0LXVzZXIiLCJnaXZlbl9uYW1lIjoicyIsImZhbWlseV9uYW1lIjoicyIsImVtYWlsIjoid3FAam1haWwuY29tIn0.gdA1eiTlDJD-9Sd47Ek5orojzReW5gK8nmM6k1JSfb1MLzio2TFHKt0wJ_E2MocC-OD8hRJZ5ogloVeTD9eCuNvKJ3oVjCb2Goys8ZvFgrTQwuT-k2tpSyLxYOcGBus0I1x12FNlMG1oa5NAOHug_A-VOGG80LNODvL-hS8IbRIiZafKAtu72l2-gYhxVNIdwkQG5UKVJvabmvhFIuG3QP1CXkZ0zQSAeP6TLk5FxgkM7oOl2sP8YNQfujI_U_C6WFxlN3Vm9h6_cPfD7fK7ToD50YeaLXulqIXwYuDYU-XEEob9QHOiBDVU9nXBjYJ2mqbpHVwfzKW4F-aDzCaFNw";
        try {
            this.keyCloakSSOAuth.verifyAndExtractRoles(this.token);
        } catch (Exception e) {
            boolean flag = e instanceof IllegalArgumentException;
            Assert.assertTrue(flag);
            Assert.assertEquals("signature verification key cannot be null.", e.getMessage());
        }
    }

    @Test
    public void testGetHeaders() throws IOException {
        Map<String, Object> headers = this.keyCloakSSOAuth.getHeaders(this.token);
        org.junit.Assert.assertNotNull(headers);
        org.junit.Assert.assertFalse(headers.isEmpty());
    }

    @Test
    public void testGetPayload() throws IOException {
        Map<String, Object> payload = this.keyCloakSSOAuth.getPayload(this.token);
        Assert.assertNotNull(payload);
        Assert.assertFalse(payload.isEmpty());
    }

    @Test
    public void testGetIssuer() throws IOException {
        Map<String, Object> payload = this.keyCloakSSOAuth.getPayload(this.token);
        String issuer = keyCloakSSOAuth.getIssuer(payload);
        org.junit.Assert.assertNotNull(issuer);
        Assert.assertEquals("http://localhost:8080/realms/testing", issuer);
    }

    @Test
    public void testGetKid() throws IOException {
        Map<String, Object> headers = this.keyCloakSSOAuth.getHeaders(this.token);
        String kid = keyCloakSSOAuth.getKid(headers);
        org.junit.Assert.assertNotNull(kid);
        Assert.assertEquals("s-V8jvo_QlRsP1WORaCwpwaH38Jp7iuJAPx9C-RXHzU", kid);
    }

    @Test
    public void testGetKidEmpty() throws IOException {
        String kidEmptyToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE3NDIyODk5NjYsImV4cCI6MTc3MzgyNTk2NiwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.QoM49yoVbAhcIjoP5j25HOG8cBR_FWiRiAuPyO7re5o";
        Map<String, Object> headers = this.keyCloakSSOAuth.getHeaders(kidEmptyToken);
        String kid = keyCloakSSOAuth.getKid(headers);
        org.junit.Assert.assertNotNull(kid);
        Assert.assertEquals("", kid);
    }
}
