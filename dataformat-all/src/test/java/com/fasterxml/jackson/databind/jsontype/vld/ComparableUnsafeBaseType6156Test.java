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
package com.fasterxml.jackson.databind.jsontype.vld;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.cfg.MapperConfig;
import com.fasterxml.jackson.databind.exc.InvalidDefinitionException;
import com.fasterxml.jackson.databind.exc.InvalidTypeIdException;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.jsontype.DefaultBaseTypeLimitingValidator;

/**
 * Regression test for CVE-2026-83557 (jackson-databind #6156) against the shaded
 * jackson-databind: {@code java.lang.Comparable} must be treated as an "unsafe"
 * polymorphic base type by {@link DefaultBaseTypeLimitingValidator}.
 */
public class ComparableUnsafeBaseType6156Test
{
    static class WrappedPolymorphicComparable {
        @JsonTypeInfo(use=JsonTypeInfo.Id.CLASS)
        public Comparable<?> value;

        protected WrappedPolymorphicComparable() { }
    }

    static class ComparablesAreOkValidator extends DefaultBaseTypeLimitingValidator
    {
        private static final long serialVersionUID = 1L;

        @Override
        protected boolean isUnsafeBaseType(MapperConfig<?> config, JavaType baseType)
        {
            // only override handling for `Comparable`
            if (baseType.hasRawClass(Comparable.class)) {
                return false;
            }
            return super.isUnsafeBaseType(config, baseType);
        }

        @Override
        protected boolean isSafeSubType(MapperConfig<?> config,
                JavaType baseType, JavaType subType)
        {
            // ... but only allow a small set of known-safe subtypes: relaxing the
            // base type check alone would leave all "gadget" types accessible
            if (baseType.hasRawClass(Comparable.class)) {
                return subType.hasRawClass(java.io.File.class);
            }
            return super.isSafeSubType(config, baseType, subType);
        }
    }

    private final ObjectMapper MAPPER = JsonMapper.builder()
            .enable(MapperFeature.BLOCK_UNSAFE_POLYMORPHIC_BASE_TYPES)
            .build();

    private static String a2q(String json) {
        return json.replace("'", "\"");
    }

    private static void verifyException(Throwable e, String match) {
        String msg = String.valueOf(e.getMessage());
        assertTrue("Expected an exception with sub-string \"" + match + "\": got \""
                + msg + "\"", msg.contains(match));
    }

    // [databind#6156]: `Comparable` is too wide a base type to allow
    @Test
    public void testPolymorphicWithComparableBaseType() throws Exception
    {
        final String JSON = a2q("{'value':['java.io.File','/tmp/stuff']}");

        try {
            /*w =*/ MAPPER.readValue(JSON, WrappedPolymorphicComparable.class);
            fail("Should not pass");
        } catch (InvalidDefinitionException e) {
            verifyException(e, "Configured");
            verifyException(e, "all subtypes of base type");
            verifyException(e, "java.lang.Comparable");
        }

        // but may be allowed with custom validator that overrides base type check
        ObjectMapper customMapper = JsonMapper.builder()
                .enable(MapperFeature.BLOCK_UNSAFE_POLYMORPHIC_BASE_TYPES)
                .polymorphicTypeValidator(new ComparablesAreOkValidator())
                .build();
        WrappedPolymorphicComparable w = customMapper.readValue(JSON,
                WrappedPolymorphicComparable.class);
        assertEquals(new java.io.File("/tmp/stuff"), w.value);

        // ... but that validator still only allows the subtypes it knows to be safe
        try {
            customMapper.readValue(a2q("{'value':['java.lang.String','stuff']}"),
                    WrappedPolymorphicComparable.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, "Could not resolve type id 'java.lang.String'");
            verifyException(e, "denied resolution");
        }
    }
}
