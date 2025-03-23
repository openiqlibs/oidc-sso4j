package io.github.openiqlibs.token.auth;

import io.jsonwebtoken.Claims;

import java.util.Set;

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
 * Interface RoleExtractor used in InAppTokenAndCerts class to extract roles from token
 * Needs to be implemented and passed implemented instance to InAppTokenAndCerts builder method {@code setRoleExtractor}
 */
public interface RoleExtractor {

    /**
    * Method can be implemented to extract roles from claims object
     * @param claims
     * @return {@code Set<String>}
    */
    Set<String> extractRoles(Claims claims);
}
