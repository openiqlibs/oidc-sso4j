package org.jakarta.sso.token.auth;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;

public abstract class SSOTokenAndCerts {

    private final Logger logger = LoggerFactory.getLogger(SSOTokenAndCerts.class);

    protected abstract String getSSO_JWKsUrl();

    protected abstract Set<String> getListOfRolesObjectKeys();

    private Map<String, PublicKey> publicKeyMap;

    protected Map<String, Object> getSSOCerts(String certsUrls) throws IOException, InterruptedException {
        ObjectMapper objectMapper = new ObjectMapper();
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(certsUrls))
                .GET()
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
            logger.error("unable to download keys from host ", e);
            throw e;
        }
    }

    protected Map<String, PublicKey> getPublicKeys(Map<String, Object> certs) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Map<String, PublicKey> publicKeys = new HashMap<String, PublicKey>();

        if (certs == null) {
            logger.error("sso error :  Invalid certs fetched");
            return publicKeys;
        }

        List<Map<String, Object>> keys = (List<Map<String, Object>>) certs.get("keys");

        for (Map<String, Object> key : keys) {
            try {
                KeyFactory keyFactory = KeyFactory.getInstance(key.get("kty").toString());
                Base64.Decoder urlDecoder = Base64.getUrlDecoder();
                BigInteger modulus = new BigInteger(1, urlDecoder.decode(key.get("n").toString()));
                BigInteger publicExponent = new BigInteger(1, urlDecoder.decode(key.get("e").toString()));
                PublicKey publicKey = keyFactory.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
                publicKeys.put(key.get("kid").toString(), publicKey);
            } catch (Exception e) {
                logger.error("sso error : Unable to generate public key from cert with kid: {}", key.get("kid").toString());
                throw e;
            }
        }

        return publicKeys;
    }

    protected Set<String> extractRoles(Claims claims) {
        Set<String> roles = new HashSet<>();
        for (String key : getListOfRolesObjectKeys()) {
            if (claims.containsKey(key)) {
                Map<String, Object> keyValueObj = (Map<String, Object>) claims.get(key);
                roles.addAll((Collection<String>) keyValueObj.get("roles"));
            } else {
                logger.error("no roles present with key {}", key);
            }
        }
        return roles;
    }

    public Set<String> getRolesOfToken(String token, String kid) throws Exception {
        Claims claims;
        try {
                PublicKey publicKey = publicKeyMap.get(kid);
                claims = Jwts.parser().verifyWith(publicKey).build().parseSignedClaims(token).getPayload();
        } catch (Exception e) {
            logger.error(e.getMessage());
            throw e;
        }
        return extractRoles(claims);
    }

    public void downloadAndStorePublicKeys() throws IOException, InterruptedException, NoSuchAlgorithmException, InvalidKeySpecException {
        logger.info("downloading public keys from {}", getSSO_JWKsUrl());
        Map<String,Object> certs = getSSOCerts(getSSO_JWKsUrl());
        publicKeyMap = getPublicKeys(certs);
    }
}
