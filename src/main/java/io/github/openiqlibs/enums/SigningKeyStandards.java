package io.github.openiqlibs.enums;

/**
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *
 * This enum is providing keys {@code secretKey} and {@code publicKey} in generate token method and
 * also can be helpful while retrieving access token and refresh token from taken pair map
 */
public enum SigningKeyStandards {
    SECRET_KEY("secretKey"),
    PUBLIC_KEY("publicKey");

    private final String keyType;

    SigningKeyStandards(String keyType) {
        this.keyType = keyType;
    }

    public String getValue() {
        return keyType;
    }
}
