package org.jakarta.sso.token.auth;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.*;

public abstract class AbstractSSOAuth {

    public abstract Set<String> verifyAndExtractRoles(String token) throws Exception;

    public Map<String, Object> getHeaders(String token) throws IOException {
        Map<String, Object> headers;
        ObjectMapper mapper = new ObjectMapper();
        String headerPart = token.substring(0, token.indexOf("."));
        headers = mapper.readValue(Base64.getDecoder().decode(headerPart), new TypeReference<>() {});
        return headers;
    }

    public Map<String, Object> getPayload(String token) throws IOException {
        Map<String, Object> payload;
        ObjectMapper mapper = new ObjectMapper();
        String payloadPart = token.substring(token.indexOf(".") + 1, token.lastIndexOf("."));
        payload = mapper.readValue(Base64.getDecoder().decode(payloadPart), new TypeReference<>() {});
        return payload;
    }

    public String getIssuer(Map<String, Object> payload) {
        return payload.get("iss").toString();
    }

    public String getKid(Map<String, Object> headers) {
        if (headers.containsKey("kid")) {
            return headers.get("kid").toString();
        }
        return "";
    }

}

