package org.jakarta.sso.token.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.jakarta.sso.enums.SigningKeyStandards;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class InAppTokenAndCerts {

    private final Logger logger = LoggerFactory.getLogger(InAppTokenAndCerts.class);

    public static final String ACCESS_TOKEN = "accessToken";

    public static final String REFRESH_TOKEN = "refreshToken";

    private String secret;

    private int accessTokenValidity;

    private int refreshTokenValidity;

    private String keyToUse;

    private String publicKeyString;

    private String privateKeyString;

    private SecretKey secretKey;

    private PublicKey publicKey;

    private PrivateKey privateKey;

    private String issuer;

    private InAppTokenAndCerts() {}

    protected void loadSecretKey() {
        logger.info("loading secret key");
        byte[] key = secret.getBytes();
        this.secretKey = Keys.hmacShaKeyFor(key);
    }

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

    public static boolean isNullOrEmptyOrBlank(String str) {
        return str == null || str.isEmpty() || str.isBlank();
    }

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
        if (accessTokenValidity == 0 || accessTokenValidity > 15) {
            throw new RuntimeException("initialize access token validity and it should not be greater than 15 minutes");
        }
        if (refreshTokenValidity == 0 || refreshTokenValidity > 24) {
            throw new RuntimeException("initialize access token validity and it should not be greater than 24 hours");
        }
    }

    protected Set<String> extractRoles(Claims claims) {
        Set<String> roles = new HashSet<>();
        if (claims.containsKey("roles")) {
            roles.addAll((Collection<String>) claims.get("roles"));
        } else {
            logger.error("no 'roles' key present to extract roles from claims");
        }
        return roles;
    }

    public Set<String> getRolesOfToken(String token) throws Exception {
        try {
            Claims claims = null;
            if (keyToUse.equals(SigningKeyStandards.SECRET_KEY.getValue())) {
                claims = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload();
            } else {
                claims = Jwts.parser().verifyWith(publicKey).build().parseSignedClaims(token).getPayload();
            }
            return extractRoles(claims);
        } catch (Exception e) {
            logger.error(e.getMessage());
            throw e;
        }
    }

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

    public static class Builder {
        private final InAppTokenAndCerts inAppTokenAndCerts;

        public Builder() {
            this.inAppTokenAndCerts = new InAppTokenAndCerts();
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
            this.inAppTokenAndCerts.loadSigningKeys();
            return this.inAppTokenAndCerts;
        }
    }
}
