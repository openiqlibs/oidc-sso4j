package io.github.openiqlibs.token.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.github.openiqlibs.enums.SigningKeyStandards;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 * Class is used to generate and validate token inside java app without third party sso
 */
public class InAppTokenAndCerts {

    private final Logger logger = LoggerFactory.getLogger(InAppTokenAndCerts.class);

    public static final String ACCESS_TOKEN = "accessToken";

    public static final String REFRESH_TOKEN = "refreshToken";

    /**
     * used to sign jwt using this secret
     */
    private String secret;

    /**
     * to set access validity of jwt access token
     */
    private int accessTokenValidity;

    /**
     * to set access validity of jwt refersh token
     */
    private int refreshTokenValidity;

    /**
     * to determine which method of signing to use secretKey or private/public Key
     */
    private String keyToUse;

    /**
     * public key pem content
     */
    private String publicKeyString;

    /**
     * private key pem content
     */
    private String privateKeyString;

    /**
     * generated secret key get stored here
     */
    private SecretKey secretKey;

    /**
     * generated public key stored here
     */
    private PublicKey publicKey;

    /**
     * generated private key stored here
     */
    private PrivateKey privateKey;

    /**
     * to set issuer
     */
    private String issuer;

    /**
     * to set audience
     */
    private String audience;

    /**
     * implemented role extractor instance
     */
    private RoleExtractor roleExtractor;

    /**
     * private constructor
     */
    private InAppTokenAndCerts() {}

    /**
     * to load secret key using secret string
     * @return SecretKey
     */
    protected void loadSecretKey() {
        logger.info("loading secret key");
        byte[] key = secret.getBytes();
        this.secretKey = Keys.hmacShaKeyFor(key);
    }

    /**
     * to load public key from public key string
     */
    private void loadPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        logger.info("loading public key");
        String publicKeyPEM = publicKeyString
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decodedKey = Base64.getDecoder().decode(publicKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(decodedKey));
    }

    /**
     * to load private key from private key string
     */
    private void loadPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        logger.info("loading private key");
        String privateKeyPEM = privateKeyString
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decodedKey = Base64.getDecoder().decode(privateKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodedKey));
    }

    /**
     * to load secret key private key based on keytouse
     */
    protected void loadSigningKeys() {
        if (keyToUse.equals(SigningKeyStandards.SECRET_KEY.getValue())) {
            loadSecretKey();
        } else {
            try {
                loadPrivateKey();
                loadPublicKey();
            } catch (Exception e) {
                logger.error(e.getMessage());
                throw new RuntimeException(e);
            }
        }
    }

    /**
     * string checking
     * @param str
     * @return boolean
     */
    public static boolean isNullOrEmptyOrBlank(String str) {
        return str == null || str.isEmpty() || str.isBlank();
    }

    /**
     * to setup RoleExtractor instance
     */
    private void setupRoleExtractor() {
        if (roleExtractor == null) {
            logger.info("setting default role extractor");
            roleExtractor = new DefaultRoleExtractor();
        }
    }

    /**
     * to validate all needed fields are not null and present
     * @throws RuntimeException
     */
    protected void validateFields() {
        if (isNullOrEmptyOrBlank(keyToUse)) {
            throw new RuntimeException("initialize signing key standard using signing key standard enum");
        }
        if (keyToUse.equals(SigningKeyStandards.SECRET_KEY.getValue())) {
            if (isNullOrEmptyOrBlank(secret)) {
                throw new RuntimeException("secret cannot be null or empty");
            }
        } else {
            if (isNullOrEmptyOrBlank(privateKeyString)) {
                throw new RuntimeException("private key string cannot be null or empty");
            }
            if (isNullOrEmptyOrBlank(publicKeyString)) {
                throw new RuntimeException("public key string cannot be null or empty");
            }
        }
        if (isNullOrEmptyOrBlank(issuer)) {
            throw new RuntimeException("issuer cannot be null or empty");
        }
        if (isNullOrEmptyOrBlank(audience)) {
            throw new RuntimeException("audience cannot be null or empty");
        }
        if (accessTokenValidity == 0 || accessTokenValidity > 15) {
            throw new RuntimeException("initialize access token validity and it should not be greater than 15 minutes");
        }
        if (refreshTokenValidity == 0 || refreshTokenValidity > 24) {
            throw new RuntimeException("initialize access token validity and it should not be greater than 24 hours");
        }
    }

    /**
     * to get roles from token and also validate token using secret or private keys
     * @param token
     * @throws Exception
     * @return Set<String>
     */
    public Set<String> getRolesOfToken(String token) throws Exception {
        try {
            Claims claims = null;
            if (keyToUse.equals(SigningKeyStandards.SECRET_KEY.getValue())) {
                claims = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload();
            } else {
                claims = Jwts.parser().verifyWith(publicKey).build().parseSignedClaims(token).getPayload();
            }
            return roleExtractor.extractRoles(claims);
        } catch (Exception e) {
            logger.error(e.getMessage());
            throw e;
        }
    }

    /**
     * to generate pair of access token and refresh token
     * @param claims
     * @param subject
     * @return Map<String, Object>
     */
    public Map<String, String> generateTokenPair(Map<String, Object> claims, String subject) {
        Map<String, String> responseTokens = new HashMap<>();
        Calendar c = Calendar.getInstance();
        c.setTime(new Date());
        Date issuedAt = c.getTime();
        c.add(Calendar.MINUTE, accessTokenValidity);
        Date accessTokenExpiry = c.getTime();
        c.add(Calendar.HOUR_OF_DAY, refreshTokenValidity);
        Date refreshTokenExpiry = c.getTime();
        responseTokens.put(ACCESS_TOKEN, doGenerateToken(claims, subject, issuedAt, accessTokenExpiry));
        responseTokens.put(REFRESH_TOKEN, doGenerateToken(claims, subject, issuedAt, refreshTokenExpiry));
        return responseTokens;
    }

    /**
     * to generate token
     * @param claims
     * @param subject
     * @param issueAt
     * @param expireAt
     * @return String
     */
    public String doGenerateToken(Map<String, Object> claims, String subject, Date issueAt, Date expireAt) {
        JwtBuilder builder = Jwts.builder().subject(subject).claims(claims)
                .issuedAt(issueAt)
                .issuer(issuer)
                .expiration(expireAt);

        if (keyToUse.equals(SigningKeyStandards.SECRET_KEY.getValue())) {
            builder.signWith(secretKey);
        } else {
            builder.signWith(privateKey);
        }
        return builder.compact();
    }

    /**
     * static inner builder class
     */
    public static class Builder {
        private final InAppTokenAndCerts inAppTokenAndCerts;

        public Builder() {
            this.inAppTokenAndCerts = new InAppTokenAndCerts();
        }

        public Builder setRoleExtractor(RoleExtractor roleExtractor) {
            this.inAppTokenAndCerts.roleExtractor = roleExtractor;
            return this;
        }

        public Builder setSecretValue(String secret) {
            this.inAppTokenAndCerts.secret = secret;
            return this;
        }

        public Builder setPublicKeyString(String publicKeyString) {
            this.inAppTokenAndCerts.publicKeyString = publicKeyString;
            return this;
        }

        public Builder setPrivateKeyString(String privateKeyString) {
            this.inAppTokenAndCerts.privateKeyString = privateKeyString;
            return this;
        }

        public Builder setIssuer(String issuer) {
            this.inAppTokenAndCerts.issuer = issuer;
            return this;
        }

        public Builder setAudience(String audience) {
            this.inAppTokenAndCerts.audience = audience;
            return this;
        }

        public Builder setAccessTokenValidityInMinutes(int validityInMinutes) {
            this.inAppTokenAndCerts.accessTokenValidity = validityInMinutes;
            return this;
        }

        public Builder setRefreshTokenValidityInHours(int validityInHours) {
            this.inAppTokenAndCerts.refreshTokenValidity = validityInHours;
            return this;
        }

        public Builder usingSigningKeyStandard(SigningKeyStandards signingKeyStandards) {
            this.inAppTokenAndCerts.keyToUse = signingKeyStandards.getValue();
            return this;
        }

        public InAppTokenAndCerts build() {
            this.inAppTokenAndCerts.validateFields();
            this.inAppTokenAndCerts.setupRoleExtractor();
            this.inAppTokenAndCerts.loadSigningKeys();
            return this.inAppTokenAndCerts;
        }
    }
}
