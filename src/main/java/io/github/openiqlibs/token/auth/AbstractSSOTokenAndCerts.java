package io.github.openiqlibs.token.auth;

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

/**
 * This abstract class is used get token related certs and validation of token.
 * Also contains useful methods for downloading and loading certs to public keys.
 * Needs to extend to use this library.
 */
public abstract class AbstractSSOTokenAndCerts {

    private final Logger logger = LoggerFactory.getLogger(AbstractSSOTokenAndCerts.class);

    /**
     * Abstract method to get sso jwks(certs) url so that can be downloaded
     * Needs to override and implement in extended class
     * Returns jwks(certs) url of sso provider
     * @return {@code String}
     */
    public abstract String getSSO_JWKsUrl();

    /**
     * Abstract method to get set of roles object keys
     * Needs to override and implement in extended class
     * Returns {@code Set<String>} roles object key
     * @return {@code Set<String>}
     */
    public abstract Set<String> getSetOfRolesObjectKeys();

    /**
     * Map of public keys which is loaded after downloading certs from given url {@code getSSO_JWKsUrl()}
     */
    private Map<String, PublicKey> publicKeyMap;

    /**
     * This method used to download certs from given certsUrl. uses java11 {@code Httpclient} to download.
     * Takes String certsUrl and returns certs map {@code Map<String, Object>}
     * @param certsUrl
     * @throws IOException
     * @throws InterruptedException
     * @return {@code Map<String,Object>}
     */
    protected Map<String, Object> getSSOCerts(String certsUrl) throws IOException, InterruptedException {
        ObjectMapper objectMapper = new ObjectMapper();
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(certsUrl))
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

    /**
     * Method is to load downloaded certs into publicKeyMap
     * @param certs
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @return Map<String, Object> publicKeys
     */
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

    /**
     * Abstract method need to be implemented in extended class which extracts roles from claims object
     * and returns set of string of roles
     * @param claims
     * @return Set<String>
     */
    protected abstract Set<String> extractRoles(Claims claims);

    /**
     * Method validates token using public keys and calls extractRole method to get roles from token
     * @param token
     * @param kid
     * @throws Exception
     * @return Set<String>
     */
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

    /**
     * Method downloads certs from url and initiate public keys using certs
     * @throws IOException
     * @throws InterruptedException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public void downloadAndStorePublicKeys() throws IOException, InterruptedException, NoSuchAlgorithmException, InvalidKeySpecException {
        logger.info("downloading public keys from {}", getSSO_JWKsUrl());
        Map<String,Object> certs = getSSOCerts(getSSO_JWKsUrl());
        publicKeyMap = getPublicKeys(certs);
    }
}
