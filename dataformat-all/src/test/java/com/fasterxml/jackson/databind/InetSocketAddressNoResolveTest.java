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

import java.net.InetSocketAddress;

import org.junit.Test;

/**
 * Regression tests for CVE-2026-54514 (jackson-databind #5951 / #6185): deserializing an
 * {@link InetSocketAddress} with the shaded jackson-databind must NOT trigger a DNS lookup
 * of the attacker-supplied host name (SSRF / DNS exfiltration), and serializing the
 * resulting unresolved IPv6 addresses must bracket the host so the port stays unambiguous.
 */
public class InetSocketAddressNoResolveTest
{
    private static final ObjectMapper MAPPER = new ObjectMapper();

    static class AddressBean {
        public InetSocketAddress address;
    }

    private static String q(String str) {
        return "\"" + str + "\"";
    }

    /*
    /**********************************************************************
    /* Deserialization: no DNS lookup
    /**********************************************************************
     */

    // [databind#5951]: host name from untrusted JSON must not be resolved
    @Test
    public void testHostAndPortIsNotResolved() throws Exception
    {
        // "localhost" always resolves, so a resolving implementation would
        // return a resolved address here
        InetSocketAddress address = MAPPER.readValue(q("localhost:9999"), InetSocketAddress.class);
        assertTrue("`InetSocketAddress` resolved localhost during deserialization: " + address,
                address.isUnresolved());
        assertNull(address.getAddress());
        assertEquals("localhost", address.getHostName());
        assertEquals(9999, address.getPort());
    }

    @Test
    public void testHostWithoutPortIsNotResolved() throws Exception
    {
        InetSocketAddress address = MAPPER.readValue(q("localhost"), InetSocketAddress.class);
        assertTrue("`InetSocketAddress` resolved localhost during deserialization: " + address,
                address.isUnresolved());
        assertEquals("localhost", address.getHostName());
        assertEquals(0, address.getPort());
    }

    @Test
    public void testAttackerHostNameIsNotResolved() throws Exception
    {
        InetSocketAddress address = MAPPER.readValue(q("ssrf-probe.attacker.invalid:80"),
                InetSocketAddress.class);
        assertTrue(address.isUnresolved());
        assertEquals("ssrf-probe.attacker.invalid", address.getHostName());
        assertEquals(80, address.getPort());
    }

    @Test
    public void testNestedPropertyIsNotResolved() throws Exception
    {
        AddressBean bean = MAPPER.readValue("{\"address\":\"localhost:8080\"}", AddressBean.class);
        assertTrue("`InetSocketAddress` resolved localhost during deserialization: " + bean.address,
                bean.address.isUnresolved());
        assertEquals("localhost", bean.address.getHostName());
        assertEquals(8080, bean.address.getPort());
    }

    @Test
    public void testIpLiteralsAreNotResolved() throws Exception
    {
        InetSocketAddress address = MAPPER.readValue(q("127.0.0.1"), InetSocketAddress.class);
        assertTrue(address.isUnresolved());
        assertEquals("127.0.0.1", address.getHostName());
        assertEquals(0, address.getPort());

        address = MAPPER.readValue(q("127.0.0.1:8080"), InetSocketAddress.class);
        assertTrue(address.isUnresolved());
        assertEquals("127.0.0.1", address.getHostName());
        assertEquals(8080, address.getPort());

        InetSocketAddress ip6 = MAPPER.readValue(
                q("2001:db8:85a3:8d3:1319:8a2e:370:7348"), InetSocketAddress.class);
        assertTrue(ip6.isUnresolved());
        assertEquals("2001:db8:85a3:8d3:1319:8a2e:370:7348", ip6.getHostName());
        assertEquals(0, ip6.getPort());

        InetSocketAddress ip6port = MAPPER.readValue(
                q("[2001:db8:85a3:8d3:1319:8a2e:370:7348]:443"), InetSocketAddress.class);
        assertTrue(ip6port.isUnresolved());
        assertEquals("[2001:db8:85a3:8d3:1319:8a2e:370:7348]", ip6port.getHostName());
        assertEquals(443, ip6port.getPort());
    }

    /*
    /**********************************************************************
    /* Serialization
    /**********************************************************************
     */

    @Test
    public void testSerializeInetSocketAddress() throws Exception
    {
        assertEquals(q("127.0.0.1:8080"),
                MAPPER.writeValueAsString(new InetSocketAddress("127.0.0.1", 8080)));
        assertEquals(q("127.0.0.1:8080"),
                MAPPER.writeValueAsString(InetSocketAddress.createUnresolved("127.0.0.1", 8080)));
        assertEquals(q("google.com:6667"),
                MAPPER.writeValueAsString(InetSocketAddress.createUnresolved("google.com", 6667)));
        assertEquals(q("[2001:db8:85a3:8d3:1319:8a2e:370:7348]:443"),
                MAPPER.writeValueAsString(new InetSocketAddress("2001:db8:85a3:8d3:1319:8a2e:370:7348", 443)));
    }

    // [databind#6185]: unresolved IPv6 literal must be bracketed like resolved one
    @Test
    public void testInetSocketAddressIPv6Unresolved() throws Exception
    {
        assertEquals(q("[2001:db8::1]:443"),
                MAPPER.writeValueAsString(InetSocketAddress.createUnresolved("2001:db8::1", 443)));
        // if host name is stored with brackets, must not bracket twice
        assertEquals(q("[2001:db8::1]:443"),
                MAPPER.writeValueAsString(InetSocketAddress.createUnresolved("[2001:db8::1]", 443)));
        // and IPv6 value read by Jackson must survive a full round-trip with port intact
        InetSocketAddress addr = MAPPER.readValue(q("[2001:db8::1]:443"), InetSocketAddress.class);
        String json = MAPPER.writeValueAsString(addr);
        assertEquals(q("[2001:db8::1]:443"), json);
        InetSocketAddress result = MAPPER.readValue(json, InetSocketAddress.class);
        assertEquals(addr.getHostName(), result.getHostName());
        assertEquals(443, result.getPort());
    }

    // Unbracketed IPv6 without port must not lose/merge its port on round-trip
    @Test
    public void testUnbracketedIPv6RoundTripKeepsPort() throws Exception
    {
        InetSocketAddress addr = MAPPER.readValue(q("2001:db8::1"), InetSocketAddress.class);
        String json = MAPPER.writeValueAsString(addr);
        assertEquals(q("[2001:db8::1]:0"), json);
        InetSocketAddress result = MAPPER.readValue(json, InetSocketAddress.class);
        assertTrue(result.isUnresolved());
        assertEquals(0, result.getPort());
    }
}
