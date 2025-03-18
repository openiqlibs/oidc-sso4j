package org.jakarta.sso.keycloak;

import org.junit.Assert;
import org.junit.Test;

import java.util.Set;


public class KeycloakSSOTokenAndCertsTest {

    KeyCloakSSOAndCerts keyCloakSSOAndCerts = new KeyCloakSSOAndCerts();
    NotExistRealmSSOAndCerts notExistRealmSSOAndCerts = new NotExistRealmSSOAndCerts();
    AnotherKeycloakSSOAndCerts anotherKeycloakSSOAndCerts = new AnotherKeycloakSSOAndCerts();
    KeyCloakSSOAuth keyCloakSSOAuth = new KeyCloakSSOAuth(anotherKeycloakSSOAndCerts);

    @Test
    public void testGetJwksUrl() {
        Assert.assertNotNull(keyCloakSSOAndCerts.getSSO_JWKsUrl());
        Assert.assertNotEquals("", keyCloakSSOAndCerts.getSSO_JWKsUrl());
    }

    @Test
    public void testGetListOfRolesObjectKeys() {
        Assert.assertNotNull(keyCloakSSOAndCerts.getListOfRolesObjectKeys());
        Assert.assertEquals(1, keyCloakSSOAndCerts.getListOfRolesObjectKeys().size());
    }

    @Test
    public void testGetSSOCertsDownloadAndLoadPublicKeys() {
        boolean exceptionFlag;
        try {
            keyCloakSSOAndCerts.downloadAndStorePublicKeys();
            exceptionFlag = false;
        } catch (Exception e) {
            exceptionFlag = true;
        }
        Assert.assertFalse(exceptionFlag);
    }

    @Test
    public void testGetSSOCertsDownloadException() {
        boolean exceptionFlag;
        try {
            notExistRealmSSOAndCerts.downloadAndStorePublicKeys();
            exceptionFlag = false;
        } catch (Exception e) {
            exceptionFlag = true;
        }
        Assert.assertTrue(exceptionFlag);
    }

    @Test
    public void testEmptyExtractRoles() throws Exception {
        String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJzLVY4anZvX1FsUnNQMVdPUmFDd3B3YUgzOEpwN2l1SkFQeDlDLVJYSHpVIn0.eyJleHAiOjE3NDIyOTYzMjcsImlhdCI6MTc0MjI5NjAyNywianRpIjoiYTlhNmE4NTAtZDRmMy00NzFiLWI2ZGItMDU5NTliN2Y5Yzg3IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy90ZXN0aW5nIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6IjhhMjA3MWVjLWU2M2MtNGQ1Zi1hNmVhLTk2ZWQzNWY4MWVmNSIsInR5cCI6IkJlYXJlciIsImF6cCI6InRlc3QtYXBwIiwic2lkIjoiZTE4ZmI4YWEtY2JhNC00YzMxLWE1NzEtMmFkMjBlNjczMDdiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyIvKiJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGVmYXVsdC1yb2xlcy10ZXN0aW5nIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwibmFtZSI6InMgcyIsInByZWZlcnJlZF91c2VybmFtZSI6InRlc3QtdXNlciIsImdpdmVuX25hbWUiOiJzIiwiZmFtaWx5X25hbWUiOiJzIiwiZW1haWwiOiJ3cUBqbWFpbC5jb20ifQ.qUPQAy2NkAvCHqhlLe85Ch7xNdqoH6_7n7P_kWrVyRiei7dcxNpdseOim-f11hfDQWy8an3rZyXU9T5xwoXV5SrdE8XdUM26-v-CSm_uIU_yyx-ddzU6D2wbED0yikqYOgbgbYk1slQKPE2xZhxBgWfGV9X0gaDauUfDeNtUkI2CRZCHcYINa5R68JiQy8xVEGdNXD11HzTi1e8WLWB1qcNVYAzF4CCyzxcaJsPhYfxzSLdbPTGsX4xIpTpFOF6wgtvXn7IEizrSl3_w1Lz4wpDz9TZiedcf0F20z-2aIoVPOeFfza05PDO6yo7dt9uydO3MSy0HTY8kxbJ8-hvkLw";
        String kid = keyCloakSSOAuth.getKid(keyCloakSSOAuth.getHeaders(token));
        anotherKeycloakSSOAndCerts.downloadAndStorePublicKeys();
        Set<String> roles = anotherKeycloakSSOAndCerts.getRolesOfToken(token, kid);
        Assert.assertNotNull(roles);
        Assert.assertEquals(0, roles.size());
    }
}
