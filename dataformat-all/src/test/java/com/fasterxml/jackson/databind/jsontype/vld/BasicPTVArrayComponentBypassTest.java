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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectMapper.DefaultTyping;
import com.fasterxml.jackson.databind.exc.InvalidTypeIdException;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;

/**
 * Regression tests for CVE-2026-54513 (jackson-databind #5981) against the shaded
 * jackson-databind: {@code BasicPolymorphicTypeValidator.allowIfSubTypeIsArray()} must not
 * approve arrays whose component type would itself be denied by the configured
 * sub-class allow-list.
 */
public class BasicPTVArrayComponentBypassTest
{
    /**
     * Records every constructor invocation; lets the tests prove that an
     *  un-allow-listed type is not actually instantiated.
     */
    static final List<String> INSTANTIATIONS = new ArrayList<>();

    /**
     * Stand-in "unsafe" type. Completely benign in itself -- only side effect is
     * recording its own instantiation. {@code final} so default typing emits no
     * per-element type id, which is the configuration the bypass exploited.
     */
    static final class FakeGadget {
        public String cmd;
        public FakeGadget() {
            INSTANTIATIONS.add(FakeGadget.class.getName());
        }
    }

    /**
     * Type that IS in the allow-list, used to verify the positive path through
     * the unwrap-then-match fall-through.
     */
    static final class SafePayload {
        public int data;
        public SafePayload() { }
    }

    static final class ObjectWrapper {
        public Object value;
        protected ObjectWrapper() { }
    }

    // With the validator engaged, a direct FakeGadget value must be denied AND the
    // same FakeGadget wrapped as FakeGadget[] must also be denied.
    @Test
    public void directGadgetAndGadgetArrayBothDenied() throws Exception
    {
        ObjectMapper mapper = mapperWithSafePayloadAndArrays();

        // (a) Direct FakeGadget: denied. Sanity check that the validator is engaged.
        final String classId = FakeGadget.class.getName();
        final String directJson = "{\"value\":[\"" + classId + "\",{\"cmd\":\"x\"}]}";
        INSTANTIATIONS.clear();
        assertDenied(mapper, directJson, classId,
                "Direct FakeGadget must be denied (no array, no SafePayload match)");
        assertEquals("FakeGadget must not be instantiated when its bare class is denied;"
                + " observed=" + INSTANTIATIONS, 0, INSTANTIATIONS.size());

        // (b) FakeGadget wrapped as FakeGadget[]: pre-fix this slipped through.
        final String arrayId = "[L" + classId + ";";
        final String arrayJson = "{\"value\":[\"" + arrayId + "\",[{\"cmd\":\"x\"}]]}";
        INSTANTIATIONS.clear();
        assertDenied(mapper, arrayJson, arrayId,
                "FakeGadget[] must be denied because FakeGadget is not allow-listed");
        assertEquals("FakeGadget must not be instantiated when its array form is denied;"
                + " observed=" + INSTANTIATIONS, 0, INSTANTIATIONS.size());
    }

    // The unwrap loop must recurse for nested arrays: FakeGadget[][] is denied too.
    @Test
    public void nestedGadgetArrayAlsoDenied() throws Exception
    {
        ObjectMapper mapper = mapperWithSafePayloadAndArrays();

        final String classId = FakeGadget.class.getName();
        final String nestedArrayId = "[[L" + classId + ";";
        final String json = "{\"value\":[\"" + nestedArrayId + "\","
                + "[[{\"cmd\":\"x\"}]]]}";
        INSTANTIATIONS.clear();
        assertDenied(mapper, json, nestedArrayId,
                "FakeGadget[][] must be denied: innermost element FakeGadget is not allow-listed");
        assertEquals("FakeGadget must not be instantiated when its nested-array form is denied;"
                + " observed=" + INSTANTIATIONS, 0, INSTANTIATIONS.size());
    }

    // Positive path: SafePayload[] is approved because the component type is allow-listed.
    @Test
    public void allowListedConcreteComponentArrayAccepted() throws Exception
    {
        ObjectMapper mapper = mapperWithSafePayloadAndArrays();

        final String arrayId = "[L" + SafePayload.class.getName() + ";";
        final String json = "{\"value\":[\"" + arrayId + "\",[{\"data\":42}]]}";

        ObjectWrapper out = mapper.readValue(json, ObjectWrapper.class);
        assertNotNull(out);
        assertNotNull(out.value);
        assertEquals(SafePayload[].class, out.value.getClass());
        SafePayload[] arr = (SafePayload[]) out.value;
        assertEquals(1, arr.length);
        assertEquals(42, arr[0].data);
    }

    // Primitive-element arrays are accepted via the primitive exemption.
    @Test
    public void primitiveComponentArrayAccepted() throws Exception
    {
        ObjectMapper mapper = mapperWithSafePayloadAndArrays();

        // JVM internal name for int[] is "[I"
        final String json = "{\"value\":[\"[I\",[1,2,3]]}";
        ObjectWrapper out = mapper.readValue(json, ObjectWrapper.class);
        assertNotNull(out);
        assertEquals(int[].class, out.value.getClass());
        assertArrayEquals(new int[] { 1, 2, 3 }, (int[]) out.value);
    }

    private static void assertDenied(ObjectMapper mapper, String json, String expectedInMsg,
            String failMsg) throws Exception
    {
        try {
            mapper.readValue(json, ObjectWrapper.class);
        } catch (InvalidTypeIdException e) {
            assertTrue("Expected message to contain '" + expectedInMsg + "', got: "
                    + e.getMessage(), e.getMessage().contains(expectedInMsg));
            return;
        }
        fail(failMsg);
    }

    private ObjectMapper mapperWithSafePayloadAndArrays() {
        PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
                .allowIfSubType(SafePayload.class)
                .allowIfSubTypeIsArray()
                .build();
        return JsonMapper.builder()
                .activateDefaultTyping(ptv, DefaultTyping.NON_FINAL)
                .build();
    }
}
