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
package com.fasterxml.jackson.databind.ext;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import org.junit.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;

/**
 * Regression tests for CVE-2026-19032 (jackson-databind #6129): {@link java.nio.file.Path}
 * deserialization of the shaded jackson-databind must only accept the "file" URI scheme
 * (or no scheme) by default, rejecting jar:, http:, s3: and other schemes.
 */
public class NioPathSchemeAllowListTest
{
    private static String q(String str) {
        return "\"" + str + "\"";
    }

    private static void verifyException(Throwable e, String match) {
        String msg = String.valueOf(e.getMessage());
        assertTrue("Expected an exception with sub-string \"" + match + "\": got \"" + msg + "\"",
                msg.contains(match));
    }

    // [databind#6129]: Only accept "file" scheme or no scheme; reject jar:, http:, s3:, etc.
    @Test
    public void testRejectNonFileSchemes() throws Exception
    {
        ObjectMapper mapper = new ObjectMapper();

        // file: scheme should work
        Path p = mapper.readValue("\"file:///tmp/foo.txt\"", Path.class);
        assertNotNull(p);

        // Bare path (no scheme) should work
        p = mapper.readValue("\"/tmp/foo.txt\"", Path.class);
        assertNotNull(p);

        // Non-file schemes should fail
        _verifyRejectScheme(mapper, "jar:http://example.com/foo.jar!/path");
        _verifyRejectScheme(mapper, "http://example.com/path");
        _verifyRejectScheme(mapper, "s3://bucket/key");
        _verifyRejectScheme(mapper, "custom://something");

        // and message should list schemes that are allowed
        try {
            mapper.readValue(q("s3://bucket/key"), Path.class);
            fail("Should not pass");
        } catch (Exception e) {
            verifyException(e, "scheme 's3' not allowed");
            verifyException(e, "allowed: [\"file\"]");
        }
    }

    // [databind#6129]: scheme matching case-insensitive, as by `Paths.get(URI)` itself
    @Test
    public void testAllowedSchemeCaseInsensitive() throws Exception
    {
        ObjectMapper mapper = new ObjectMapper();

        for (String input : new String[] {
                "FILE:///tmp/foo.txt", "FiLe:///tmp/foo.txt"
        }) {
            Path p = mapper.readValue(q(input), Path.class);
            assertNotNull(p);
            assertEquals(Paths.get("/tmp", "foo.txt").toAbsolutePath(), p.toAbsolutePath());
        }
    }

    // [databind#6129]: allowed schemes may be overridden
    @Test
    public void testCustomAllowedSchemes() throws Exception
    {
        // Case-insensitive both ways: allow-list entry in upper case, input in lower
        ObjectMapper mapper = _mapperWithSchemes(Arrays.asList("FILE"));
        Path p = mapper.readValue(q("file:///tmp/foo.txt"), Path.class);
        assertNotNull(p);
        assertEquals(Paths.get("/tmp", "foo.txt").toAbsolutePath(), p.toAbsolutePath());

        // But if "file" not included, it gets rejected like any other scheme
        mapper = _mapperWithSchemes(Arrays.asList("jar", "jrt"));
        try {
            mapper.readValue(q("file:///tmp/foo.txt"), Path.class);
            fail("Should have thrown for scheme in: file:///tmp/foo.txt");
        } catch (Exception e) {
            verifyException(e, "scheme 'file' not allowed");
            verifyException(e, "allowed: [\"jar\", \"jrt\"]");
        }

        // Scheme-less values, however, are always accepted
        assertNotNull(mapper.readValue(q("/tmp/foo.txt"), Path.class));

        // and empty allow-list is legal, if unhelpful
        _verifyRejectScheme(_mapperWithSchemes(Collections.<String>emptyList()),
                "file:///tmp/foo.txt");
    }

    // [databind#6129]: providers only visible via Thread context class loader are
    // still usable (see [databind#2120]) -- but only for schemes that are allowed
    @Test
    public void testAllowedSchemeViaContextClassLoader() throws Exception
    {
        final String input = CustomSchemeFsProvider.SCHEME + ":///foo.txt";
        final ClassLoader origLoader = Thread.currentThread().getContextClassLoader();
        // Registration is not at root of test classpath, so provider is NOT one of
        // installed ones (that is, not found by `Paths.get(URI)`) unless added like so:
        final URL serviceRoot = getClass().getResource("/tcclfs/");
        assertNotNull(serviceRoot);
        Thread.currentThread().setContextClassLoader(
                new URLClassLoader(new URL[] { serviceRoot }, origLoader));

        try {
            // First: not allowed by default, and must be rejected without provider lookup
            _verifyRejectScheme(new ObjectMapper(), input);

            // But if allowed, gets resolved via context class loader
            ObjectMapper mapper = _mapperWithSchemes(
                    Arrays.asList(CustomSchemeFsProvider.SCHEME));
            Path p = mapper.readValue(q(input), Path.class);
            assertEquals(Paths.get("/tmp/jackson-test-fs/foo.txt"), p);
        } finally {
            Thread.currentThread().setContextClassLoader(origLoader);
        }
    }

    @Test
    public void testNullAllowedSchemes() throws Exception
    {
        try {
            new NioPathDeserializer(null);
            fail("Should not pass");
        } catch (IllegalArgumentException e) {
            verifyException(e, "`allowedSchemes` must not be null");
        }
    }

    private ObjectMapper _mapperWithSchemes(Collection<String> allowedSchemes) {
        SimpleModule module = new SimpleModule();
        module.addDeserializer(Path.class, new NioPathDeserializer(allowedSchemes));
        return JsonMapper.builder().addModule(module).build();
    }

    private void _verifyRejectScheme(ObjectMapper mapper, String input) {
        try {
            mapper.readValue(q(input), Path.class);
            fail("Should have thrown for scheme in: " + input);
        } catch (Exception e) {
            // expected - handleWeirdStringValue will throw by default
            verifyException(e, "not allowed for Path deserialization");
        }
    }
}
