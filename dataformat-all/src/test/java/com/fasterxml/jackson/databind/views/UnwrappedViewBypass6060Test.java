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

import org.junit.Test;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import com.fasterxml.jackson.annotation.JsonView;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import com.fasterxml.jackson.databind.json.JsonMapper;

/**
 * Regression tests for CVE-2026-59889 (jackson-databind #6060) against the shaded
 * jackson-databind: {@code @JsonView} must be honored for {@code @JsonUnwrapped}
 * Field/Setter properties (and the builder / creator-based variants that go
 * through the same unwrapped-property handling).
 */
// [databind#6060]: `@JsonView` by-passed for `@JsonUnwrapped` Field/Setter properties
public class UnwrappedViewBypass6060Test
{
    public static class PublicView {}
    public static class AdminView extends PublicView {}

    public static class AccountFlags {       // admin-only block
        public String role;
        public boolean approved;
        public long creditBalance;
    }
    public static class Registration {       // bound at the public registration endpoint
        @JsonView(PublicView.class) public String email;
        @JsonView(PublicView.class) public String password;
        @JsonView(AdminView.class) @JsonUnwrapped public AccountFlags flags;   // admin-only, unwrapped
    }
    public static class Control {            // identical block, NOT unwrapped
        @JsonView(PublicView.class) public String email;
        @JsonView(AdminView.class)  public AccountFlags flags;
    }

    public static class RegistrationWithSetters {   // same as Registration, but via setters
        String email;
        String password;
        AccountFlags flags;

        @JsonView(PublicView.class)
        public void setEmail(String email) { this.email = email; }

        @JsonView(PublicView.class)
        public void setPassword(String password) { this.password = password; }

        @JsonView(AdminView.class) @JsonUnwrapped
        public void setFlags(AccountFlags flags) { this.flags = flags; }
    }

    // Same as Registration, but bound through a creator: unwrapped Field is
    // populated on the property-based (creator) path
    public static class RegistrationWithCreator {
        final String email;

        @JsonView(PublicView.class) public String password;
        @JsonView(AdminView.class) @JsonUnwrapped public AccountFlags flags;

        @JsonCreator
        public RegistrationWithCreator(@JsonProperty("email") String email) {
            this.email = email;
        }
    }

    // Same as Registration, but bound through a builder
    @JsonDeserialize(builder = RegistrationViaBuilder.Builder.class)
    public static class RegistrationViaBuilder {
        final String email, password;
        final AccountFlags flags;

        RegistrationViaBuilder(String email, String password, AccountFlags flags) {
            this.email = email;
            this.password = password;
            this.flags = flags;
        }

        @JsonPOJOBuilder(withPrefix = "with")
        public static class Builder {
            String email, password;
            AccountFlags flags;

            @JsonView(PublicView.class)
            public Builder withEmail(String email) { this.email = email; return this; }

            @JsonView(PublicView.class)
            public Builder withPassword(String password) { this.password = password; return this; }

            @JsonView(AdminView.class) @JsonUnwrapped
            public Builder withFlags(AccountFlags flags) { this.flags = flags; return this; }

            public RegistrationViaBuilder build() {
                return new RegistrationViaBuilder(email, password, flags);
            }
        }
    }

    private static final ObjectMapper MAPPER = JsonMapper.builder().build();

    @Test
    public void testUnwrappedBypass() throws Exception {
        ObjectMapper mapper = sharedMapper();

        String jsonC = a2q("{'email':'e','flags':{'role':'ADMIN','approved':true,'creditBalance':1000000}}");
        Control c = mapper.readerWithView(PublicView.class)
                .forType(Control.class)
                .readValue(jsonC);
        assertEquals("e", c.email);
        assertNull("expected control flag to be null in PublicView read", c.flags);

        String jsonR = a2q("{'email':'mallory@evil.test','password':'pw',"
                + "'role':'ADMIN','approved':true,'creditBalance':1000000}");
        Registration r = mapper.readerWithView(PublicView.class)
                .forType(Registration.class)
                .readValue(jsonR);
        assertEquals("mallory@evil.test", r.email);
        assertEquals("pw", r.password);
        // JsonUnwrapped flag in Registration class may affect this
        assertNull("expected registration flag to be null in PublicView read", r.flags);
    }

    // Negative control: AdminView read MUST populate the unwrapped admin-only block,
    // so the PublicView assertion above is not passing vacuously.
    @Test
    public void testUnwrappedVisibleInAdminView() throws Exception {
        ObjectMapper mapper = sharedMapper();

        String jsonR = a2q("{'email':'admin@corp.test','password':'pw',"
                + "'role':'ADMIN','approved':true,'creditBalance':1000000}");
        Registration r = mapper.readerWithView(AdminView.class)
                .forType(Registration.class)
                .readValue(jsonR);
        assertEquals("admin@corp.test", r.email);
        assertNotNull("expected registration flag to be populated in AdminView read", r.flags);
        assertEquals("ADMIN", r.flags.role);
        assertEquals(1000000, r.flags.creditBalance);
    }

    @Test
    public void testUnwrappedBypassWithSetters() throws Exception {
        ObjectMapper mapper = sharedMapper();

        String jsonR = a2q("{'email':'mallory@evil.test','password':'pw',"
                + "'role':'ADMIN','approved':true,'creditBalance':1000000}");
        RegistrationWithSetters r = mapper.readerWithView(PublicView.class)
                .forType(RegistrationWithSetters.class)
                .readValue(jsonR);
        assertEquals("mallory@evil.test", r.email);
        assertEquals("pw", r.password);
        // JsonUnwrapped flag in RegistrationWithSetters class may affect this
        assertNull("expected registration flag to be null in PublicView read", r.flags);
    }

    // Negative control for the setter variant: AdminView read MUST populate flags.
    @Test
    public void testUnwrappedVisibleInAdminViewWithSetters() throws Exception {
        ObjectMapper mapper = sharedMapper();

        String jsonR = a2q("{'email':'admin@corp.test','password':'pw',"
                + "'role':'ADMIN','approved':true,'creditBalance':1000000}");
        RegistrationWithSetters r = mapper.readerWithView(AdminView.class)
                .forType(RegistrationWithSetters.class)
                .readValue(jsonR);
        assertEquals("admin@corp.test", r.email);
        assertNotNull("expected registration flag to be populated in AdminView read", r.flags);
        assertEquals("ADMIN", r.flags.role);
        assertEquals(1000000, r.flags.creditBalance);
    }

    // Creator-based bean: the unwrapped Field is filled after the creator runs
    // (creator property last, so the preceding regular property gets buffered)
    @Test
    public void testUnwrappedBypassWithCreator() throws Exception {
        ObjectMapper mapper = sharedMapper();

        String jsonR = a2q("{'password':'pw','role':'ADMIN','approved':true,"
                + "'creditBalance':1000000,'email':'mallory@evil.test'}");
        RegistrationWithCreator r = mapper.readerWithView(PublicView.class)
                .forType(RegistrationWithCreator.class)
                .readValue(jsonR);
        assertEquals("mallory@evil.test", r.email);
        assertEquals("pw", r.password);
        assertNull("expected registration flag to be null in PublicView read", r.flags);
    }

    @Test
    public void testUnwrappedVisibleInAdminViewWithCreator() throws Exception {
        ObjectMapper mapper = sharedMapper();

        String jsonR = a2q("{'password':'pw','role':'ADMIN','approved':true,"
                + "'creditBalance':1000000,'email':'admin@corp.test'}");
        RegistrationWithCreator r = mapper.readerWithView(AdminView.class)
                .forType(RegistrationWithCreator.class)
                .readValue(jsonR);
        assertEquals("admin@corp.test", r.email);
        assertNotNull("expected registration flag to be populated in AdminView read", r.flags);
        assertEquals("ADMIN", r.flags.role);
        assertEquals(1000000, r.flags.creditBalance);
    }

    // Builder-based bean: the unwrapped builder "with" method
    @Test
    public void testUnwrappedBypassWithBuilder() throws Exception {
        ObjectMapper mapper = sharedMapper();

        String jsonR = a2q("{'email':'mallory@evil.test','password':'pw',"
                + "'role':'ADMIN','approved':true,'creditBalance':1000000}");
        RegistrationViaBuilder r = mapper.readerWithView(PublicView.class)
                .forType(RegistrationViaBuilder.class)
                .readValue(jsonR);
        assertEquals("mallory@evil.test", r.email);
        assertEquals("pw", r.password);
        assertNull("expected registration flag to be null in PublicView read", r.flags);
    }

    @Test
    public void testUnwrappedVisibleInAdminViewWithBuilder() throws Exception {
        ObjectMapper mapper = sharedMapper();

        String jsonR = a2q("{'email':'admin@corp.test','password':'pw',"
                + "'role':'ADMIN','approved':true,'creditBalance':1000000}");
        RegistrationViaBuilder r = mapper.readerWithView(AdminView.class)
                .forType(RegistrationViaBuilder.class)
                .readValue(jsonR);
        assertEquals("admin@corp.test", r.email);
        assertNotNull("expected registration flag to be populated in AdminView read", r.flags);
        assertEquals("ADMIN", r.flags.role);
        assertEquals(1000000, r.flags.creditBalance);
    }

    private static ObjectMapper sharedMapper() {
        return MAPPER;
    }

    private static String a2q(String json) {
        return json.replace('\'', '"');
    }
}
