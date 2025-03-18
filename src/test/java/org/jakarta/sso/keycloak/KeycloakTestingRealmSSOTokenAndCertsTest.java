package org.jakarta.sso.keycloak;

import org.jakarta.sso.abstracttests.AbstractSSOTokenAndCertsTest;
import org.jakarta.sso.token.auth.AbstractSSOAuth;
import org.jakarta.sso.token.auth.SSOTokenAndCerts;

public class KeycloakTestingRealmSSOTokenAndCertsTest extends AbstractSSOTokenAndCertsTest {

    private AnotherKeycloakSSOAndCerts anotherKeycloakSSOAndCerts = new AnotherKeycloakSSOAndCerts();

    @Override
    protected SSOTokenAndCerts getSsoTokenAndCerts() {
        return new KeyCloakSSOAndCerts();
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
        return "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJET1VtVXU1UEpId25KMEp1bmdnN3prMjFkQkoydXM0eW9uUU1oZmZjM3U4In0.eyJleHAiOjE3NDIzMDI5MTAsImlhdCI6MTc0MjMwMjYxMCwianRpIjoiZDYxODM5ODktMmMxNy00Njg4LWI5M2UtN2RiMWY0ZTc3MjMzIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy90ZXN0aW5nIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6ImVmMDgwNWVhLWU1YTktNDY2MS1hYWRlLTU0Mjg2NzY3ZTQ3MyIsInR5cCI6IkJlYXJlciIsImF6cCI6InRlc3QtYXBwIiwic2lkIjoiMTJmNDgyOTQtZGQ5Ni00NjNlLWJiNjktOWJhZTJmNGVhMjk2IiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyIvKiJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGVmYXVsdC1yb2xlcy10ZXN0aW5nIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoiZW1haWwgcHJvZmlsZSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwibmFtZSI6ImggaCIsInByZWZlcnJlZF91c2VybmFtZSI6InRlc3QtdXNlciIsImdpdmVuX25hbWUiOiJoIiwiZmFtaWx5X25hbWUiOiJoIiwiZW1haWwiOiJ3cUBqbWFpbC5jb20ifQ.n4di5rufklfAbGNmMQoBRG4f-H73bQ9mLn7AfIkPDjvQHZcITOIEd05ZxR_nVNVjs_evJxeljkDttBSpAv2Mt1CEy5QyrqKOAbzCfncLgwFHTGKMvASYUwYVhMuCR61U2gZSBUwUBkqvCOgr-OguaOjybHBU8r3nOvaoPHd4V6Qrd-guUQFJHl_n5ytj2Pi0g40cqCfdTRwIcbcHxFHM0mdMU30qUoy7roQfdR6PSwXgQsVLanfLtoGlfy7C0tl9QnF6sSAGfTLL7x3sgqwhlAkvQgmgOsKOroDM_alnlZn8RYXBNHuEG28gdW-BfOhFCoaH73fnBKoC2aUUdYphvw";
    }
}
