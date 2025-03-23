package io.github.openiqlibs.token.auth;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.*;

/**
 * This is abstract class which needs to extend while using this library
 * it also contains some useful methods for jwt decoding
 */
public abstract class AbstractSSOAuth {

    /**
     * This method is used to get extracted roles and do validation of jwt token using {@code getRolesOfToken()} method
     * from various class which extends {@code AbstractSSOTokenAndCerts} abstract class
     * Needs to override and implement in extended class
     * Takes jwt token and Returns {@code Set<String>}
     * @param token
     * @return {@code Set<String>}
     * @throws Exception
     */
    public abstract Set<String> verifyAndExtractRoles(String token) throws Exception;

    /**
     * This method is used to get headers of jwt token
     * Takes jwt token and return headers map {@code Map<String, Object>}
     * @param token
     * @return {@code Map<String, Object>}
     */
    public Map<String, Object> getHeaders(String token) throws IOException {
        Map<String, Object> headers;
        ObjectMapper mapper = new ObjectMapper();
        String headerPart = token.substring(0, token.indexOf("."));
        headers = mapper.readValue(Base64.getDecoder().decode(headerPart), new TypeReference<>() {});
        return headers;
    }

    /**
     * This method is used to get payload of jwt token
     * Takes jwt token and return payload map {@code Map<String, Object>}
     * @param token
     * @return {@code Map<String, Object>}
     */
    public Map<String, Object> getPayload(String token) throws IOException {
        Map<String, Object> payload;
        ObjectMapper mapper = new ObjectMapper();
        String payloadPart = token.substring(token.indexOf(".") + 1, token.lastIndexOf("."));
        payload = mapper.readValue(Base64.getDecoder().decode(payloadPart), new TypeReference<>() {});
        return payload;
    }

    /**
     * This method is used to issuer from jwt token
     * Takes payload map {@code Map<String, Object>} and return issuer string of key {@code iss}
     * @param payload
     * @return String issuer
     */
    public String getIssuer(Map<String, Object> payload) {
        return payload.get("iss").toString();
    }

    /**
     * This method is used to get kid of jwt token
     * Takes header map {@code Map<String, Object>} and return kid string from header map of key {@code kid}.
     * if kid not present return empty String {@code ""}
     * @param headers
     * @return String kid
     */
    public String getKid(Map<String, Object> headers) {
        if (headers.containsKey("kid")) {
            return headers.get("kid").toString();
        }
        return "";
    }

}

