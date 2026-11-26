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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.InetAddress;

import org.junit.Test;

import com.fasterxml.jackson.databind.exc.InvalidFormatException;

/**
 * Regression tests for CVE-2026-77310 (jackson-databind #6058 / #6116): deserializing an
 * {@link InetAddress} with the shaded jackson-databind must NOT trigger a DNS lookup of an
 * attacker-supplied host name (SSRF / DNS exfiltration); only IP address literals are accepted.
 */
public class InetAddressNoDnsLookupTest
{
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static String q(String str) {
        return "\"" + str + "\"";
    }

    @Test
    public void testInetAddress() throws Exception
    {
        // Valid IPv4 address
        InetAddress address = MAPPER.readValue(q("127.0.0.1"), InetAddress.class);
        assertEquals("127.0.0.1", address.getHostAddress());

        // Valid IPv6 address
        InetAddress ip6 = MAPPER.readValue(
                q("2001:db8:85a3:8d3:1319:8a2e:370:7348"), InetAddress.class);
        assertEquals("2001:db8:85a3:8d3:1319:8a2e:370:7348", ip6.getHostAddress());

        // IPv6 loopback
        InetAddress loopback6 = MAPPER.readValue(q("::1"), InetAddress.class);
        assertEquals("0:0:0:0:0:0:0:1", loopback6.getHostAddress());
    }

    @Test
    public void testInetAddressNoDNSLookup() throws Exception
    {
        // [databind#6058]: should NOT perform DNS lookup -- only IP address literals accepted
        expectInvalidInetAddress("localhost");
        expectInvalidInetAddress("google.com");
        // starts off looking like an IP address (edge case)
        expectInvalidInetAddress("1.2.3.4.example.com");
        // punycode
        expectInvalidInetAddress("xn--bcher-kva.example.com");
    }

    @Test
    public void testInetAddressNonAsciiDigits() throws Exception
    {
        // [databind#6116], follow-up to [databind#6058]: Character.digit() accepts
        // non-ASCII digits, but InetAddress.getByName() only treats ASCII literals as
        // addresses and resolves the rest via DNS, so these must be rejected too.
        // NOTE: unicode escapes used on purpose -- non-ASCII digit forms are visually
        // hard to tell apart from the ASCII ones they mimic.
        expectInvalidInetAddress("\uFF11\uFF12\uFF17.0.0.1"); // full-width "127".0.0.1
        expectInvalidInetAddress("\u0661\u0662\u0667.0.0.1"); // Arabic-Indic "127".0.0.1
        expectInvalidInetAddress("\uFF12001:db8::1"); // full-width digit in IPv6 hextet
        expectInvalidInetAddress("fe80::\uFF11"); // full-width digit in IPv6 hextet
        // and same goes for non-ASCII hex letters (radix 16), not just digits
        expectInvalidInetAddress("\uFF41bcd::1"); // full-width "a"bcd::1
    }

    private void expectInvalidInetAddress(String address) throws Exception {
        try {
            InetAddress result = MAPPER.readValue(q(address), InetAddress.class);
            fail("Should not pass for '" + address + "', got: " + result);
        } catch (InvalidFormatException e) {
            assertTrue("Unexpected exception message: " + e.getMessage(),
                    e.getMessage().contains("Not a valid IP address string literal"));
        }
    }
}
