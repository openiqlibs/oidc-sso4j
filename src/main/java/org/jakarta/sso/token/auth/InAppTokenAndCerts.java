package org.jakarta.sso.token.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.jakarta.sso.enums.SigningKeyStandards;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.util.*;

public class InAppTokenAndCerts {

    private final Logger logger = LoggerFactory.getLogger(InAppTokenAndCerts.class);

    private String secret;

    private int accessTokenValidity;

    private int refreshTokenValidity;

    private String keyToUse;

    private SecretKey secretKey;

    private String issuer;

    private InAppTokenAndCerts() {}

    protected void loadSecretKey() {
        byte[] key = secret.getBytes();
        this.secretKey = Keys.hmacShaKeyFor(key);
    }

    protected void loadSigningKeys() {
        if (keyToUse.equals(SigningKeyStandards.SECRET_KEY.getValue())) {
            loadSecretKey();
        } else {
            //load private-public key pair
        }
    }

    protected void validateFields() {
        if (secret == null || secret.isEmpty() || secret.isBlank()) {
            throw new RuntimeException("secret cannot be null or empty");
        }
        if (issuer == null || issuer.isEmpty() || issuer.isBlank()) {
            throw new RuntimeException("issuer cannot be null or empty");
        }
        if (accessTokenValidity == 0 || accessTokenValidity > 15) {
            throw new RuntimeException("initialize access token validity and it should not be greater than 15 minutes");
        }
        if (refreshTokenValidity == 0 || refreshTokenValidity > 24) {
            throw new RuntimeException("initialize access token validity and it should not be greater than 24 hours");
        }
        if (keyToUse == null || keyToUse.isEmpty() || keyToUse.isBlank()) {
            throw new RuntimeException("initialize signing key standard using signing key standard enum");
        }
    }

    protected Set<String> extractRoles(Claims claims) {
        Set<String> roles = new HashSet<>();
        if (claims.containsKey("roles")) {
            roles.addAll((Collection<String>) claims.get("roles"));
        } else {
            throw new RuntimeException("no 'roles' key present to extract roles from claims");
        }
        return roles;
    }

    public Set<String> getRolesOfToken(String token) throws Exception {
        try {
            Claims claims = null;
            if (keyToUse.equals(SigningKeyStandards.SECRET_KEY.getValue())) {
                claims = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload();
            } else {
                //claims = Jwts.parser().verifyWith(publicKey).build().parseSignedClaims(token).getPayload();
            }
            return extractRoles(claims);
        } catch (Exception e) {
            logger.error(e.getMessage());
            throw e;
        }
    }

    public Map<String, String> generateTokenPair(Map<String, Object> claims, String subject, String issuer) {
        Map<String, String> responseTokens = new HashMap<>();
        Calendar c = Calendar.getInstance();
        c.setTime(new Date());
        Date issuedAt = c.getTime();
        c.add(Calendar.MINUTE, accessTokenValidity);
        Date accessTokenExpiry = c.getTime();
        c.add(Calendar.HOUR_OF_DAY, refreshTokenValidity);
        Date refreshTokenExpiry = c.getTime();
        responseTokens.put("accessToken", doGenerateToken(claims, subject, issuedAt, accessTokenExpiry));
        responseTokens.put("refreshToken", doGenerateToken(claims, subject, issuedAt, refreshTokenExpiry));
        return responseTokens;
    }

    public String doGenerateToken(Map<String, Object> claims, String subject, Date issueAt, Date expireAt) {
        if (issuer == null || issuer.isEmpty() || issuer.isBlank()) {
            throw new RuntimeException("issuer cannot be null");
        }
        JwtBuilder builder = Jwts.builder().subject(subject).claims(claims)
                .issuedAt(issueAt)
                .issuer(issuer)
                .expiration(expireAt);

        if (keyToUse.equals(SigningKeyStandards.SECRET_KEY.getValue())) {
            builder.signWith(secretKey);
        } else {
            //builder.signWith(publicKey);
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
