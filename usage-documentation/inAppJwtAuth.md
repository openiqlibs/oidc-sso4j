# How to use `InAppTokenAndCerts` to create and validate your own tokens (In Spring Boot)
To create object on `InAppTokenAndCerts` follow the code.
```java
@Configuration
public class InAppJwtConfiguration {

    @Value("${jwt.encrypt.secret}")
    private String secret;

    @Bean
    public InAppTokenAndCerts getInAppTokenAndCerts() {
        return new InAppTokenAndCerts.Builder()
                .setAccessTokenValidityInMinutes(10)
                .setRefreshTokenValidityInHours(1)
                .setAudience("inApp")
                .setIssuer("inApp")
                .usingSigningKeyStandard(SigningKeyStandards.SECRET_KEY)
                .setSecretValue(secret)
                .build();
    }
}
```
here we are injecting secret using properties file with name `jwt.encrypt.secret` also we can inject all other things as well like this for example 
audience, issuer, access token validity etc.

**Note:** here secret string should be of atleast 40 characters as per hmac security standards.

Now you can inject this in same way we did for `KeycloakSSO` and use inside `verifyAndExtractRoles()` method for your own issuer.

```java
@Component
public class SSOAuth extends AbstractSSOAuth {

    @Autowired
    private InAppTokenAndCerts inAppTokenAndCerts;

    @Override

    public Set<String> verifyAndExtractRoles(String token) throws Exception {
        try {
            String issuer = getIssuer(getPayload(token));
            String kid = getKid(getHeaders(token));
            if (issuer.equals("inApp")) {
                return inAppTokenAndCerts.getRolesOfToken(token);
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

Finally, in same way inside `Filter` class you can convert roles to `Collection<GrantedAuthority>` and pass to `SecurityContext`.
