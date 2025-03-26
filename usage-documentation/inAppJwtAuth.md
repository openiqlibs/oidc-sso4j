# How to use `InAppTokenAndCerts` to create and validate your own tokens (In Spring Boot)
To create object on `InAppTokenAndCerts` follow the code.

## Using secret key
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

**Note:** here secret string should be of atleast >= 256 bits (nearly 40 characters) as per hmac security standards.

Now you can inject this in same way we did for `KeycloakSSO` and use inside `verifyAndExtractRoles()` method for your own issuer.

## Using private and public key
To create `InAppTokenAndCerts` object using private and public key standards follow this code.
```java
@Configuration
public class InAppJwtConfiguration {

    @Value("${jwt.private.key}")
    private String privateString;

    @Value("${jwt.public.key}")
    private String publicString;

    @Bean
    public InAppTokenAndCerts getInAppTokenAndCerts() {
        return new InAppTokenAndCerts.Builder()
                .setAccessTokenValidityInMinutes(10)
                .setRefreshTokenValidityInHours(1)
                .setAudience("testing")
                .setIssuer("testing")
                .usingSigningKeyStandard(SigningKeyStandards.PUBLIC_KEY)
                .setPrivateKeyString(privateString)
                .setPublicKeyString(publicString)
                .build();
    }
}
```
here we are setting encryption decryption standards to public key and injecting this using 
`jwt.private.key` and `jwt.public.key` in properties file.
In properties set this variables using environment variable like below.
```properties
jwt.private.key=${private_key}
jwt.public.key=${public_key}
```
## Custom RoleExtractor
in above codes we haven't specified any roleExtractor so by default `DefaulRoleExtractor` gets injected and used. 
but if we want to use our own custom RoleExtractor then we can implement as follows.
```java
@Configuration
public class InAppJwtConfiguration {

    @Value("${jwt.private.key}")
    private String privateString;

    @Value("${jwt.public.key}")
    private String publicString;

    @Bean
    public InAppTokenAndCerts getInAppTokenAndCerts() {
        return new InAppTokenAndCerts.Builder()
                .setAccessTokenValidityInMinutes(10)
                .setRefreshTokenValidityInHours(1)
                .setRoleExtractor(claims -> Set.of())
                .setAudience("testing")
                .setIssuer("testing")
                .usingSigningKeyStandard(SigningKeyStandards.PUBLIC_KEY)
                .setPrivateKeyString(privateString)
                .setPublicKeyString(publicString)
                .build();
    }
}
```
here we have implemented anonymous method of `RoleExtractor` interface, but you can use class object which implements this interface.

Now extend `AbstractSSOAuth` and implement method.

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
