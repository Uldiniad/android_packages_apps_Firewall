/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.net.IpPrefix;

import org.junit.Test;

import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

public class ListParserTest {
    private final List<String> mEntries = new ArrayList<>();
    private final ListParser.Entries mSink = new ListParser.Entries() {
        @Override
        public void domain(String name, boolean subdomains) {
            mEntries.add((subdomains ? "*." : "") + name);
        }

        @Override
        public void prefix(IpPrefix prefix) {
            mEntries.add(prefix.toString());
        }
    };

    private ListParser.Result parse(boolean plainSubdomains, String... lines) throws IOException {
        return ListParser.parse(new StringReader(String.join("\n", lines)), plainSubdomains,
                1000, 1_000_000, mSink);
    }

    @Test
    public void takesTheEntriesOfEachFormat() throws IOException {
        ListParser.Result result = parse(true,
                "0.0.0.0 ads.example",
                "127.0.0.1 Tracker.Example. other.example",
                "plain.example",
                "*.wild.example",
                "||adblock.example^",
                "||important.example^$important",
                "198.51.100.7",
                "203.0.113.0/24 ; SBL123",
                "2001:db8::/32 # documentation",
                "{\"cidr\":\"192.0.2.0/24\",\"sblid\":\"SBL1\",\"rir\":\"arin\"}",
                "bücher.example");
        assertEquals(List.of("ads.example", "tracker.example", "other.example",
                "*.plain.example", "*.wild.example", "*.adblock.example", "*.important.example",
                "198.51.100.7/32", "203.0.113.0/24", "2001:db8::/32", "192.0.2.0/24",
                "*.xn--bcher-kva.example"), mEntries);
        assertEquals(11, result.lines());
        assertEquals(12, result.taken());
        assertEquals(0, result.refused());
        assertFalse(result.tooBig());
    }

    @Test
    public void skipsAllowRulesPartialRulesAndHostsBoilerplate() throws IOException {
        ListParser.Result result = parse(false,
                "[Adblock Plus 2.0]",
                "! Title: Example",
                "# A comment",
                "",
                "@@||allowed.example^",
                "||path.example/ads^",
                "||options.example^$third-party",
                "127.0.0.1 localhost",
                "::1 ip6-localhost ip6-loopback",
                "0.0.0.0 0.0.0.0",
                "two words here");
        assertEquals(List.of(), mEntries);
        assertEquals(4, result.lines());
        assertEquals(0, result.taken());
        assertEquals(0, result.refused());
    }

    @Test
    public void refusesWhatWouldCutTheDeviceOff() throws IOException {
        ListParser.Result result = parse(true,
                "10.1.2.3", "192.168.1.1", "100.64.0.1", "127.0.0.1", "169.254.1.1",
                "172.16.0.0/12", "192.0.0.4", "224.0.0.251", "255.255.255.255", "0.0.0.0/8",
                "fc00::1", "fe80::1", "ff02::1", "::1", "64:ff9b::808:808",
                "32.0.0.0/3", "2000::/3",
                "com", "bad..name", "a".repeat(64) + ".example", "0.0.0.0 1.2.3.4",
                "198.51.100.0/24");
        assertEquals(List.of("198.51.100.0/24"), mEntries);
        assertEquals(22, result.lines());
        assertEquals(1, result.taken());
        assertEquals(21, result.refused());
    }

    @Test
    public void readsWhatHeadersSayInEachListsOwnForm() throws IOException {
        ListParser.Result hagezi = parse(true,
                "\uFEFF# Title: HaGeZi's Example",
                "# Version: 2026.1115.1554.35",
                "# Number of entries: 2",
                "one.example",
                "two.example",
                "# Number of entries: 9");
        assertEquals("HaGeZi's Example", hagezi.title());
        assertEquals("2026.1115.1554.35", hagezi.version());
        assertEquals(2, hagezi.declared());
        assertEquals(2, hagezi.lines());

        ListParser.Result adblock = parse(false, "! Number of entries: 3,566", "||a.example^");
        assertEquals(3566, adblock.declared());

        ListParser.Result spamhaus = parse(false,
                "{\"cidr\":\"198.51.100.0/24\",\"sblid\":\"SBL1\",\"rir\":\"arin\"}",
                "{\"type\":\"metadata\",\"timestamp\":1763164800,\"size\":81,\"records\":1}");
        assertEquals(1, spamhaus.declared());
        assertEquals(1, spamhaus.lines());

        assertEquals(ListParser.NO_COUNT, parse(true, "plain.example").declared());
    }

    @Test
    public void readsACountrysBlocksWhoseRangesRunPastTheLongestLine() throws IOException {
        StringBuilder ranges = new StringBuilder();
        for (int i = 0; i < 400; i++) {
            ranges.append("\"45.").append(i / 256).append('.').append(i % 256).append(".0/24\", ");
        }
        ListParser.Result result = parse(false,
                "{",
                "  \"country\": \"Andorra\",",
                "  \"countryCode\": \"AD\",",
                "  \"prefixes\": {",
                "    \"ipv4\": [ " + ranges + "\"10.0.0.0/8\" ],",
                "    \"ipv6\": [ \"2a01:fb00::/29\" ]",
                "  }",
                "}");
        assertEquals("45.0.0.0/24", mEntries.get(0));
        assertEquals("2a01:fb00::/29", mEntries.get(400));
        assertEquals(402, result.lines());
        assertEquals(401, result.taken());
        assertEquals(1, result.refused());
        assertFalse(result.tooBig());
    }

    @Test
    public void stopsPastItsLimits() throws IOException {
        ListParser.Result many = ListParser.parse(
                new StringReader("a.example\nb.example\nc.example\n"), false, 2, 1000, mSink);
        assertTrue(many.tooBig());

        ListParser.Result chars = ListParser.parse(
                new StringReader("a.example\n".repeat(100)), false, 1000, 50, mSink);
        assertTrue(chars.tooBig());

        ListParser.Result line = ListParser.parse(
                new StringReader("x".repeat(5000) + ".example\nok.example\n"), false, 1000,
                100_000, mSink);
        assertFalse(line.tooBig());
        assertEquals(2, line.lines());
        assertEquals(1, line.taken());
    }
}
