/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH
 * under one or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership. Camunda licenses this file to you under the Apache License,
 * Version 2.0; you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.fasterxml.jackson.databind;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

/**
 * Regression tests for CVE-2026-59888 (jackson-databind #5974): with the shaded
 * jackson-databind, an ignored property (via {@code @JsonIgnore} or
 * {@code @JsonProperty(access = READ_ONLY)}) must stay ignored for deserialization
 * when a {@link PropertyNamingStrategy} renames it.
 * <p>
 * {@code POJOPropertiesCollector} records the implicit name (e.g. "internalRoles") of
 * an ignored property before the naming strategy renames it (e.g. to "internal_roles");
 * without the rename-aware ignoral propagation the renamed JSON key slipped past the
 * ignoral check and was bound (for Records: to the constructor parameter; for POJOs:
 * through the "getter-as-setter" path of a Collection/Map valued property).
 */
public class IgnoreNamingStrategy5974Test
{
    // Explicitly included getter, but setter marked @JsonIgnore: property must be
    // serialization-only and the renamed key must not reach the getter-as-setter
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    static class IgnoredSetterRolesBean {
        public String username;

        private List<String> roles = new ArrayList<String>();

        @JsonProperty
        public List<String> getInternalRoles() {
            return roles;
        }

        @JsonIgnore
        public void setInternalRoles(List<String> internalRoles) {
            roles = internalRoles;
        }
    }

    // Read-only (serialization-only) Collection property
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    static class ReadOnlyRolesBean {
        public String username;

        private List<String> roles = new ArrayList<String>();

        @JsonProperty(access = JsonProperty.Access.READ_ONLY)
        public List<String> getInternalRoles() {
            return roles;
        }
    }

    // Read-only (serialization-only) Map property
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    static class ReadOnlyPermissionsBean {
        public String username;

        private Map<String, String> permissions = new LinkedHashMap<String, String>();

        @JsonProperty(access = JsonProperty.Access.READ_ONLY)
        public Map<String, String> getInternalPermissions() {
            return permissions;
        }
    }

    // Same as IgnoredSetterRolesBean, but without @JsonNaming (strategy set on mapper)
    static class PlainIgnoredSetterRolesBean {
        public String username;

        private List<String> roles = new ArrayList<String>();

        @JsonProperty
        public List<String> getInternalRoles() {
            return roles;
        }

        @JsonIgnore
        public void setInternalRoles(List<String> internalRoles) {
            roles = internalRoles;
        }
    }

    // POJO analog of the Record case from the upstream test
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    static class SensitivePojo {
        public String username;
        @JsonIgnore
        public String internalRole;
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static String a2q(String json) {
        return json.replace("'", "\"");
    }

    /*
    /**********************************************************************
    /* Exploit: renamed key of an ignored property must not be bound
    /**********************************************************************
     */

    @Test
    public void testNormalDeserialization() throws Exception
    {
        IgnoredSetterRolesBean result = MAPPER.readValue(a2q("{'username':'alice'}"),
                IgnoredSetterRolesBean.class);
        assertEquals("alice", result.username);
        assertTrue(result.getInternalRoles().isEmpty());
    }

    @Test
    public void testRenamedIgnoredSetterBypass() throws Exception
    {
        IgnoredSetterRolesBean result = MAPPER.readValue(
                a2q("{'username':'alice','internal_roles':['ADMIN']}"),
                IgnoredSetterRolesBean.class);
        assertEquals("alice", result.username);
        assertEquals(Collections.emptyList(), result.getInternalRoles());
    }

    @Test
    public void testRenamedReadOnlyCollectionBypass() throws Exception
    {
        ReadOnlyRolesBean result = MAPPER.readValue(
                a2q("{'username':'alice','internal_roles':['ADMIN']}"),
                ReadOnlyRolesBean.class);
        assertEquals("alice", result.username);
        assertEquals(Collections.emptyList(), result.getInternalRoles());
    }

    @Test
    public void testRenamedReadOnlyMapBypass() throws Exception
    {
        ReadOnlyPermissionsBean result = MAPPER.readValue(
                a2q("{'username':'alice','internal_permissions':{'admin':'true'}}"),
                ReadOnlyPermissionsBean.class);
        assertEquals("alice", result.username);
        assertTrue(result.getInternalPermissions().isEmpty());
    }

    // Naming strategy configured globally on the mapper instead of via @JsonNaming
    @Test
    public void testRenamedIgnoredSetterBypassWithMapperStrategies() throws Exception
    {
        PropertyNamingStrategy[] strategies = new PropertyNamingStrategy[] {
                PropertyNamingStrategies.SNAKE_CASE,
                PropertyNamingStrategies.UPPER_CAMEL_CASE,
                PropertyNamingStrategies.KEBAB_CASE,
                PropertyNamingStrategies.LOWER_CASE,
                PropertyNamingStrategies.LOWER_DOT_CASE
        };
        String[] renamedKeys = new String[] {
                "internal_roles", "InternalRoles", "internal-roles", "internalroles", "internal.roles"
        };
        for (int i = 0; i < strategies.length; ++i) {
            ObjectMapper mapper = new ObjectMapper()
                    .setPropertyNamingStrategy(strategies[i]);
            PlainIgnoredSetterRolesBean result = mapper.readValue(
                    "{\"" + renamedKeys[i] + "\":[\"ADMIN\"]}",
                    PlainIgnoredSetterRolesBean.class);
            assertEquals("Ignored property bound via renamed key '" + renamedKeys[i] + "'",
                    Collections.emptyList(), result.getInternalRoles());
        }
    }

    // Without a naming strategy the ignoral was already effective; must stay so
    @Test
    public void testIgnoredSetterWithoutNamingStrategy() throws Exception
    {
        PlainIgnoredSetterRolesBean result = MAPPER.readValue(
                a2q("{'username':'alice','internalRoles':['ADMIN']}"),
                PlainIgnoredSetterRolesBean.class);
        assertEquals("alice", result.username);
        assertEquals(Collections.emptyList(), result.getInternalRoles());
    }

    // Non-Record path drops the @JsonIgnore property entirely before renaming; lock in
    // that an ignored field cannot be populated via the renamed key either
    @Test
    public void testRenamedIgnoredPojoFieldBypass() throws Exception
    {
        ObjectMapper mapper = new ObjectMapper()
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        SensitivePojo result = mapper.readValue(
                a2q("{'username':'alice','internal_role':'ADMIN'}"),
                SensitivePojo.class);
        assertEquals("alice", result.username);
        assertNull(result.internalRole);
    }

    /*
    /**********************************************************************
    /* Serialization must be unaffected
    /**********************************************************************
     */

    @Test
    public void testSerializationStillUsesRenamedName() throws Exception
    {
        IgnoredSetterRolesBean bean = new IgnoredSetterRolesBean();
        bean.username = "alice";
        bean.getInternalRoles().add("USER");
        assertEquals(a2q("{'username':'alice','internal_roles':['USER']}"),
                MAPPER.writeValueAsString(bean));

        ReadOnlyRolesBean roBean = new ReadOnlyRolesBean();
        roBean.username = "bob";
        roBean.getInternalRoles().add("USER");
        assertEquals(a2q("{'username':'bob','internal_roles':['USER']}"),
                MAPPER.writeValueAsString(roBean));
    }
}
