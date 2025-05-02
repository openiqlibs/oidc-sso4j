package io.github.openiqlibs.models;

import java.util.List;

public class JwtCerts {

    private List<CertConfigurations> keys;

    public List<CertConfigurations> getKeys() {
        return keys;
    }

    public void setKeys(List<CertConfigurations> keys) {
        this.keys = keys;
    }
}
