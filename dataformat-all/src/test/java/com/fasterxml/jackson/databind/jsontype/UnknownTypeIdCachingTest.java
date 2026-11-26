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
package com.fasterxml.jackson.databind.jsontype;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Test;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.DatabindContext;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.annotation.JsonTypeIdResolver;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.jsontype.impl.TypeIdResolverBase;

/**
 * Regression test for CVE-2026-91776 (jackson-databind #6203) against the shaded
 * jackson-databind: caching of type ids in the type id lookup cache of the (long-lived,
 * shared) {@link TypeDeserializer}: unresolvable ids handled via the "nullifying"
 * fallback (whose use depends on reader configuration) are not retained, whereas
 * ones handled via {@code defaultImpl} are, like resolvable type ids (cache being
 * bounded in size).
 */
public class UnknownTypeIdCachingTest
{
    static final AtomicInteger RESOLVE_COUNT = new AtomicInteger();

    @JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY,
            property = "type", defaultImpl = DefaultAnimal.class)
    @JsonTypeIdResolver(CountingIdResolver.class)
    static abstract class Animal {
        public String name;
    }

    static class Dog extends Animal { }

    static class DefaultAnimal extends Animal { }

    @JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY,
            property = "type")
    @JsonTypeIdResolver(CountingIdResolver.class)
    static abstract class Animal2 {
        public String name;
    }

    static class Dog2 extends Animal2 { }

    static class Wrapper {
        public Animal animal;
    }

    static class Wrapper2 {
        public Animal2 animal;
    }

    public static class CountingIdResolver extends TypeIdResolverBase
    {
        private static final long serialVersionUID = 1L;

        @Override
        public JsonTypeInfo.Id getMechanism() { return JsonTypeInfo.Id.NAME; }

        @Override
        public String idFromValue(Object value) {
            return idFromValueAndType(value, value.getClass());
        }

        @Override
        public String idFromValueAndType(Object value, Class<?> type) {
            return type.getSimpleName();
        }

        @Override
        public JavaType typeFromId(DatabindContext ctxt, String id) {
            RESOLVE_COUNT.incrementAndGet();
            if ("Dog".equals(id)) {
                return ctxt.constructType(Dog.class);
            }
            if ("Dog2".equals(id)) {
                return ctxt.constructType(Dog2.class);
            }
            return null;
        }
    }

    private final ObjectMapper MAPPER = JsonMapper.builder().build();

    private static String a2q(String json) {
        return json.replace("'", "\"");
    }

    // Unknown type ids resolved via `defaultImpl` ARE cached (bounded by cache size
    // limit), as `defaultImpl` does not depend on reader configuration
    @Test
    public void cachingOfUnknownIdsWithDefaultImpl() throws Exception
    {
        RESOLVE_COUNT.set(0);
        ObjectReader r = MAPPER.readerFor(Wrapper.class);

        for (int i = 0; i < 10; ++i) {
            Wrapper w = r.readValue(a2q(
                    "{'animal':{'type':'bogus-"+i+"','name':'Rex'}}"));
            assertTrue(w.animal instanceof DefaultAnimal);
        }
        // Every distinct unknown id has to be resolved once
        assertEquals(10, RESOLVE_COUNT.get());

        // ... and repeating a single unknown id resolves it just once, too
        RESOLVE_COUNT.set(0);
        for (int i = 0; i < 10; ++i) {
            Wrapper w = r.readValue(a2q("{'animal':{'type':'bogus','name':'Rex'}}"));
            assertTrue(w.animal instanceof DefaultAnimal);
        }
        assertEquals(1, RESOLVE_COUNT.get());

        // Whereas known type ids ARE cached: resolved just once
        RESOLVE_COUNT.set(0);
        for (int i = 0; i < 10; ++i) {
            Wrapper w = r.readValue(a2q("{'animal':{'type':'Dog','name':'Rex'}}"));
            assertTrue(w.animal instanceof Dog);
            assertEquals("Rex", w.animal.name);
        }
        assertEquals(1, RESOLVE_COUNT.get());
    }

    // Unknown type ids must not be cached: `FAIL_ON_INVALID_SUBTYPE` disabled variant
    @Test
    public void noCachingOfUnknownIdsWhenNullifying() throws Exception
    {
        RESOLVE_COUNT.set(0);
        ObjectReader r = MAPPER.readerFor(Wrapper2.class)
                .without(DeserializationFeature.FAIL_ON_INVALID_SUBTYPE);

        for (int i = 0; i < 10; ++i) {
            Wrapper2 w = r.readValue(a2q(
                    "{'animal':{'type':'bogus-"+i+"','name':'Rex'}}"));
            assertNull(w.animal);
        }
        assertEquals(10, RESOLVE_COUNT.get());

        RESOLVE_COUNT.set(0);
        for (int i = 0; i < 10; ++i) {
            r.readValue(a2q("{'animal':{'type':'bogus','name':'Rex'}}"));
        }
        assertEquals(10, RESOLVE_COUNT.get());

        RESOLVE_COUNT.set(0);
        for (int i = 0; i < 10; ++i) {
            Wrapper2 w = r.readValue(a2q("{'animal':{'type':'Dog2','name':'Rex'}}"));
            assertTrue(w.animal instanceof Dog2);
        }
        assertEquals(1, RESOLVE_COUNT.get());
    }
}
