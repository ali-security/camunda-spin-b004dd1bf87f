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
package com.fasterxml.jackson.databind.views;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import com.fasterxml.jackson.annotation.JsonView;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import com.fasterxml.jackson.databind.exc.InvalidDefinitionException;
import com.fasterxml.jackson.databind.json.JsonMapper;

/**
 * Regression tests for CVE-2026-54518 (jackson-databind #5971) against the shaded
 * jackson-databind: {@code @JsonView} must be honored for view-restricted creator
 * parameters (and buffered view-restricted properties) of POJOs that also have a
 * {@code @JsonUnwrapped} property (bean and builder variants).
 */
public class UnwrappedCreatorViewBypass5971Test
{
    static class PublicV { }
    static class AdminV extends PublicV { }

    static class Extra {
        public String note;
    }

    static class UnwrappedCreatorBean {
        final String name;
        final String password;

        @JsonUnwrapped
        public Extra extra;

        @JsonCreator
        public UnwrappedCreatorBean(@JsonProperty("name") String n,
                @JsonProperty("password") @JsonView(AdminV.class) String p) {
            name = n;
            password = p;
        }
    }

    @JsonDeserialize(builder = UnwrappedCreatorUser.Builder.class)
    static class UnwrappedCreatorUser {
        final String name, password;
        final Extra extra;

        UnwrappedCreatorUser(String n, String p, Extra e) {
            name = n;
            password = p;
            extra = e;
        }

        @JsonPOJOBuilder(withPrefix = "with")
        static class Builder {
            final String name, password;
            Extra extra;

            @JsonCreator
            public Builder(@JsonProperty("name") String n,
                    @JsonProperty("password") @JsonView(AdminV.class) String p) {
                name = n;
                password = p;
            }

            @JsonUnwrapped
            public Builder withExtra(Extra e) { extra = e; return this; }

            public UnwrappedCreatorUser build() {
                return new UnwrappedCreatorUser(name, password, extra);
            }
        }
    }

    // 2-arg creator plus a view-restricted setter: the setter value seen between
    // the creator properties gets buffered on the unwrapped creator path (#5969)
    static class UnwrappedSetterBean {
        final String name, city;
        protected String password;

        @JsonUnwrapped
        public Extra extra;

        @JsonCreator
        public UnwrappedSetterBean(@JsonProperty("name") String n,
                @JsonProperty("city") String c) {
            name = n;
            city = c;
        }

        @JsonView(AdminV.class)
        public void setPassword(String p) { password = p; }
    }

    @JsonDeserialize(builder = UnwrappedSetterUser.Builder.class)
    static class UnwrappedSetterUser {
        final String name, city, password;
        final Extra extra;

        UnwrappedSetterUser(String n, String c, String p, Extra e) {
            name = n;
            city = c;
            password = p;
            extra = e;
        }

        @JsonPOJOBuilder(withPrefix = "with")
        static class Builder {
            final String name, city;
            String password;
            Extra extra;

            @JsonCreator
            public Builder(@JsonProperty("name") String n,
                    @JsonProperty("city") String c) {
                name = n;
                city = c;
            }

            @JsonView(AdminV.class)
            public Builder withPassword(String p) { password = p; return this; }

            @JsonUnwrapped
            public Builder withExtra(Extra e) { extra = e; return this; }

            public UnwrappedSetterUser build() {
                return new UnwrappedSetterUser(name, city, password, extra);
            }
        }
    }

    // The advisory's model: view-restricted `@JsonUnwrapped` creator parameter
    static class Address {
        @JsonView(AdminV.class)
        public String street;

        @JsonView(PublicV.class)
        public String city;
    }

    static class UnwrappedParamUser {
        @JsonView(PublicV.class)
        public final String name;

        @JsonView(AdminV.class)
        public final Address address;

        @JsonCreator
        public UnwrappedParamUser(
                @JsonProperty("name") @JsonView(PublicV.class) String name,
                @JsonView(AdminV.class) @JsonUnwrapped Address address) {
            this.name = name;
            this.address = address;
        }
    }

    private final ObjectMapper MAPPER = JsonMapper.builder().build();

    @Test
    public void testUnwrappedBeanViewHonoredForCreatorProp() throws Exception {
        String json = a2q("{'password':'BYPASS','note':'n','name':'alice'}");
        UnwrappedCreatorBean b = MAPPER.readerFor(UnwrappedCreatorBean.class)
                .withView(PublicV.class).readValue(json);
        assertEquals("alice", b.name);
        assertNotNull(b.extra);
        assertEquals("n", b.extra.note);
        assertNull("password should be hidden by active view", b.password);
    }

    @Test
    public void testUnwrappedBeanAdminViewStillWritesCreatorProp() throws Exception {
        String json = a2q("{'password':'OK','note':'n','name':'alice'}");
        UnwrappedCreatorBean b = MAPPER.readerFor(UnwrappedCreatorBean.class)
                .withView(AdminV.class).readValue(json);
        assertEquals("OK", b.password);
        assertEquals("n", b.extra.note);
    }

    @Test
    public void testUnwrappedBuilderViewHonoredForCreatorProp() throws Exception {
        String json = a2q("{'password':'BYPASS','note':'n','name':'alice'}");
        UnwrappedCreatorUser u = MAPPER.readerFor(UnwrappedCreatorUser.class)
                .withView(PublicV.class).readValue(json);
        assertEquals("alice", u.name);
        assertNotNull(u.extra);
        assertEquals("n", u.extra.note);
        assertNull("password should be hidden by active view", u.password);
    }

    @Test
    public void testUnwrappedBuilderAdminViewStillWritesCreatorProp() throws Exception {
        String json = a2q("{'password':'OK','note':'n','name':'alice'}");
        UnwrappedCreatorUser u = MAPPER.readerFor(UnwrappedCreatorUser.class)
                .withView(AdminV.class).readValue(json);
        assertEquals("OK", u.password);
        assertEquals("n", u.extra.note);
    }

    @Test
    public void testUnwrappedBeanViewHonoredForBufferedProp() throws Exception {
        // password placed BETWEEN the two creator props -> hits the buffering branch
        String json = a2q("{'name':'alice','password':'BYPASS','note':'n','city':'NY'}");
        UnwrappedSetterBean b = MAPPER.readerFor(UnwrappedSetterBean.class)
                .withView(PublicV.class).readValue(json);
        assertEquals("alice", b.name);
        assertEquals("NY", b.city);
        assertNotNull(b.extra);
        assertEquals("n", b.extra.note);
        assertNull("password should be hidden by active view", b.password);
    }

    @Test
    public void testUnwrappedBeanAdminViewStillWritesBufferedProp() throws Exception {
        String json = a2q("{'name':'alice','password':'OK','note':'n','city':'NY'}");
        UnwrappedSetterBean b = MAPPER.readerFor(UnwrappedSetterBean.class)
                .withView(AdminV.class).readValue(json);
        assertEquals("OK", b.password);
        assertEquals("n", b.extra.note);
    }

    @Test
    public void testUnwrappedBuilderViewHonoredForBufferedProp() throws Exception {
        String json = a2q("{'name':'alice','password':'BYPASS','note':'n','city':'NY'}");
        UnwrappedSetterUser u = MAPPER.readerFor(UnwrappedSetterUser.class)
                .withView(PublicV.class).readValue(json);
        assertEquals("alice", u.name);
        assertEquals("NY", u.city);
        assertNotNull(u.extra);
        assertEquals("n", u.extra.note);
        assertNull("password should be hidden by active view", u.password);
    }

    @Test
    public void testUnwrappedBuilderAdminViewStillWritesBufferedProp() throws Exception {
        String json = a2q("{'name':'alice','password':'OK','note':'n','city':'NY'}");
        UnwrappedSetterUser u = MAPPER.readerFor(UnwrappedSetterUser.class)
                .withView(AdminV.class).readValue(json);
        assertEquals("OK", u.password);
        assertEquals("n", u.extra.note);
    }

    // The advisory's exact vector: a `@JsonView(AdminV) @JsonUnwrapped` creator
    // parameter must never be populated while reading with PublicV. This version
    // rejects `@JsonUnwrapped` creator parameters outright, so it cannot be bound.
    @Test
    public void testUnwrappedCreatorParamNotPopulatedOutsideView() throws Exception {
        String json = a2q("{'name':'alice','street':'1 Main St','city':'Springfield'}");
        UnwrappedParamUser result;
        try {
            result = MAPPER.readerWithView(PublicV.class)
                    .forType(UnwrappedParamUser.class)
                    .readValue(json);
        } catch (InvalidDefinitionException e) {
            assertTrue("Unexpected failure: " + e.getMessage(),
                    e.getMessage().contains("@JsonUnwrapped"));
            return;
        }
        assertEquals("alice", result.name);
        assertNull("@JsonView(AdminV) @JsonUnwrapped creator parameter was populated"
                + " in PublicV: " + result.address, result.address);
    }

    private static String a2q(String json) {
        return json.replace('\'', '"');
    }
}
