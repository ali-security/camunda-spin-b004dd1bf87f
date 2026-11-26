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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectMapper.DefaultTyping;
import com.fasterxml.jackson.databind.exc.InvalidTypeIdException;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

/**
 * Tests for [CVE-2026-110879] wrt {@link BasicPolymorphicTypeValidator.Builder#allowIfSubTypeIsArray()}
 * (see [databind#2534]): arrays of abstract or interface element types are no longer
 * accepted without allow-listing the element type, except for {@code Number[]}.
 */
public class BasicPTVNumberArrayTest
{
    static abstract class Base2534 {
        public int x = 3;
    }

    static final class ObjectWrapper {
        public Object value;

        protected ObjectWrapper() { }
        public ObjectWrapper(Object v) { value = v; }
    }

    // [CVE-2026-110879]: `Number` is not abstract-like wrt gadgets: accepted
    // without allow-listing (elements are scalars or have type ids of their own)
    @Test
    public void testNumberArrayAccepted() throws Exception {
        ObjectMapper mapper = JsonMapper.builder()
                .activateDefaultTyping(BasicPolymorphicTypeValidator.builder()
                        .allowIfSubTypeIsArray()
                        .build(), DefaultTyping.NON_FINAL)
                .build();
        final Number[] input = new Number[] { 1, 2.5 };
        ObjectWrapper w = mapper.readValue(mapper.writeValueAsString(new ObjectWrapper(input)),
                ObjectWrapper.class);
        assertEquals(Number[].class, w.value.getClass());
        assertArrayEquals(input, (Number[]) w.value);

        // but not other abstract element types
        final String json = mapper.writeValueAsString(new ObjectWrapper(new Base2534[0]));
        try {
            mapper.readValue(json, ObjectWrapper.class);
            fail("Should not pass");
        } catch (InvalidTypeIdException e) {
            verifyException(e, "$Base2534");
        }
    }

    private static void verifyException(Throwable e, String expectedInMsg)
    {
        final String msg = e.getMessage();
        assertTrue("Expected message to contain '" + expectedInMsg + "', got: " + msg,
                msg != null && msg.contains(expectedInMsg));
    }
}
