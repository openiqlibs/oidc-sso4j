# Guide to `oidc-sso4j` in spring-boot

## Include Dependency
include the `oidc-sso4j` dependency in your project `pom.xml`
```xml
<dependency>
    <groupId>io.github.openiqlibs</groupId>
    <artifactId>oidc-sso4j</artifactId>
    <version>1.0.1</version>
</dependency>
```

## Extends `AbstractSSOTokenAndCerts` class and implement required methods
```java
@Component
public class KeycloakSSO extends AbstractSSOTokenAndCerts {

    @Value("${keycloak.certs}")
    private String keycloakCertsUrl; //keycloak certs url ex-> http://localhost:8080/realms/testing/protocol/openid-connect/certs

    @Override
    public String getSSO_JWKsUrl() {
        return keycloakCertsUrl;
    }

    @Override
    public Set<String> getSetOfRolesObjectKeys() {
        return Set.of("realm_access");
    }

    @Override
    protected Set<String> extractRoles(Claims claims) {
        Set<String> roles = new HashSet<>();
        for (String key : getSetOfRolesObjectKeys()) {
            if (claims.containsKey(key)) {
                Map<String, Object> keyObj = (Map<String, Object>) claims.get(key);
                roles.addAll((Collection<String>) keyObj.get("roles"));
            } else {
                System.out.println("no roles with key " + key);
            }
        }
        return roles;
    }

    @PostConstruct
    public void setupKeys() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InterruptedException {
        downloadAndStorePublicKeys();
    }
}
```
Need to extend `AbstractSSOTokenAndCerts` and implement methods `getSSO_JWKsUrl()`, `getSetOfRolesObjectKeys()` and `extractRoles()`.
Here `keycloakCertsUrl` is injected through properties file with name `keycloak.certs`. `getSetOfRolesObjectKeys()` will return set of roles key name. 
for example here how payload of keycloak jwt looks like.
```json
{
  "exp": 1742897394,
  "iat": 1742897094,
  "jti": "d1c34505-c32c-4c27-8631-0983fec3d866",
  "iss": "http://localhost:8080/realms/testing",
  "aud": "account",
  "sub": "23fd8f1f-855d-4bd3-a8ad-b14b512ecbdc",
  "typ": "Bearer",
  "azp": "test-app",
  "sid": "d22600ab-4f37-4c7b-b269-e2acd3ad9a43",
  "acr": "1",
  "allowed-origins": [
    "/*"
  ],
  "realm_access": {
    "roles": [
      "default-roles-testing",
      "offline_access",
      "uma_authorization"
    ]
  },
  "resource_access": {
    "account": {
      "roles": [
        "manage-account",
        "manage-account-links",
        "view-profile"
      ]
    }
  },
  "scope": "profile email",
  "email_verified": false,
  "name": "a a",
  "preferred_username": "test-user",
  "given_name": "a",
  "family_name": "a",
  "email": "wq@jmail.com"
}
```
Here if you see `roles` is inside `realm_access` object  and to extract that we need to first get the `realm_access` object and then `roles`.

From the above json you can see how we have implemented `extractRoles()` methods to extract roles and return using `Set<String>`.

Next is `setupKeys()` which is used to call `downloadAndStorePublicKeys()` method of abstract class. this must be annotated with `@PostConstruct` so that all public keys will be download and initialized during startup of app.

## Extend `AbstractSSOAuth` class and implement `verifyAndExtractRoles()` method
```java
@Component
public class SSOAuth extends AbstractSSOAuth {

    @Autowired
    private KeycloakSSO keycloakSSO;

    @Override
    public Set<String> verifyAndExtractRoles(String token) throws Exception {
        try {
            String issuer = getIssuer(getPayload(token));
            String kid = getKid(getHeaders(token));
            if (issuer.equals("http://localhost:8080/realms/testing")) {
                return keycloakSSO.getRolesOfToken(token, kid);
            } else if (issuer.equals("another issuer")) {
                //return anotherRealmOrIdpSSO.getRolesOfToken(token);
            } else {
                throw new RuntimeException("not a valid issuer");
            }
        } catch (Exception e) {
            throw e;
        }
    }
}
```
Here `KeycloakSSO` is class we created earlier and injected here. and we have implemented `verifyAndExtractRoles()` method of `AbstractSSOAuth` class.
we are getting `issuer` and `kid` using `getIssuer(getPayload(token))` and `getKid(getHeaders(token))` methods.
and using issuer now we can decide which sso class to use like for example if we have another issuer or different realm issuer other than keycloak then we can use that class `getRolesOfToken()` method to validate and extract roles of token.

if you don't care about role just want to validate token then you can implement above class like following.
```java
@Component
public class SSOAuth extends AbstractSSOAuth {

    @Autowired
    private KeycloakSSO keycloakSSO;

    @Override
    public Set<String> verifyAndExtractRoles(String token) throws Exception {
        try {
            String issuer = getIssuer(getPayload(token));
            String kid = getKid(getHeaders(token));
            if (issuer.equals("http://localhost:8080/realms/testing")) {
                return keycloakSSO.getRolesOfToken(token, kid);
            } else if (issuer.equals("another issuer")) {
                //return anotherRealmOrIdpSSO.getRolesOfToken(token);
            } else {
                throw new RuntimeException("not a valid issuer");
            }
        } catch (Exception e) {
            throw e;
        }
    }
    
    public boolean isAbleToValidate(String token) {
        boolean validateFlag;
        try {
            verifyAndExtractRoles(token);
            validateFlag = true;
        } catch (Exception e) {
            validateFlag = false;
        }
        return validateFlag;
    }
}
```
here you can use `isAbleToValidate` method to validate token if you don't care about roles of user.

Finally, these methods you can call in any `Filter` class which extends `OncePerRequestFilter` class
and then turn this `Set` of extracted roles into `Collection<GrantedAuthority>` and pass to `SecurityContext`.

To check how to use InAppJwt that is not with keycloak but creating and validating your own tokens check this [guide](inAppJwtAuth.md).
