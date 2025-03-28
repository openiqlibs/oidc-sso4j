package io.github.openiqlibs.token.auth;


import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.HashSet;
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
 * Class is default implementation of RoleExtractor interface
 */
public class DefaultRoleExtractor implements RoleExtractor {

    private Logger logger = LoggerFactory.getLogger(DefaultRoleExtractor.class);

    @Override
    public Set<String> extractRoles(Claims claims) {
        Set<String> roles = new HashSet<>();
        if (claims.containsKey("roles")) {
            roles.addAll((Collection<String>) claims.get("roles"));
        } else {
            logger.error("no 'roles' key present to extract roles from claims");
        }
        return roles;
    }
}
