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
 * This enum is providing defined roles object keys {@code realm_access} and {@code resource_access}
 */
public enum KeycloakScopes {

    REALM_ACCESS("realm_access"),
    RESOURCE_ACCESS("resource_access");

    private String value;

    KeycloakScopes(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
