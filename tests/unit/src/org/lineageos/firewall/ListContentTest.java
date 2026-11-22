/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import android.net.IpPrefix;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;

/** Lists as the firewall app hands them to the service, and as netd finds names in them. */
public class ListContentTest {
    // fw_domain_hash() of each name, as netd's lookup check computes it.
    private static final long EXAMPLE_COM = 0x6aacb3674df27a40L;
    private static final long ADS_EXAMPLE_COM = 0x757aba95a2d67c43L & ~1L;

    @Test
    public void keysAreNetdsHashesWithTheSubdomainBit() {
        assertEquals(EXAMPLE_COM, ListContent.nameKey("example.com", false));
        assertEquals(EXAMPLE_COM | 1, ListContent.nameKey("example.com", true));
        assertEquals(ADS_EXAMPLE_COM, ListContent.nameKey("ads.example.com", false));
    }

    @Test
    public void eachNameIsKeptOnceWithItsWidestEntry() {
        ListContent.Builder builder = new ListContent.Builder();
        builder.domain("ads.example.com", false);
        builder.domain("example.com", false);
        builder.domain("example.com", true);
        builder.domain("ads.example.com", false);
        builder.prefix(new IpPrefix("203.0.113.0/24"));
        builder.prefix(new IpPrefix("203.0.113.0/24"));
        ListContent content = builder.build();
        assertArrayEquals(new long[] {EXAMPLE_COM | 1, ADS_EXAMPLE_COM}, content.names);
        assertEquals(List.of(new IpPrefix("203.0.113.0/24")), content.ranges);
    }

    @Test
    public void contentReadsBackAsItWasWritten() throws IOException {
        ListContent.Builder builder = new ListContent.Builder();
        builder.domain("example.com", true);
        builder.domain("ads.example.com", false);
        builder.prefix(new IpPrefix("2001:db8::/32"));
        builder.prefix(new IpPrefix("203.0.113.0/24"));
        ListContent content = builder.build();
        ByteArrayOutputStream written = new ByteArrayOutputStream();
        content.write(written);
        assertEquals(content.size(), written.size());

        DataInputStream in = new DataInputStream(new ByteArrayInputStream(written.toByteArray()));
        ListContent.Header header = ListContent.Header.read(in);
        ByteArrayOutputStream names = new ByteArrayOutputStream();
        ListContent.copyNames(in, header.names(), names);
        assertEquals(content.ranges, ListContent.readRanges(in, header.ranges()));
        ByteBuffer file = ByteBuffer.wrap(names.toByteArray()).order(ByteOrder.LITTLE_ENDIAN);
        assertEquals(ListContent.NAMES_MAGIC, file.getLong());
        assertEquals(2, file.getLong());
        assertEquals(content.names[0], file.getLong());
        assertEquals(content.names[1], file.getLong());
    }

    @Test
    public void keysOutOfOrderAreRefused() {
        ByteBuffer bytes = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        bytes.putLong(ADS_EXAMPLE_COM).putLong(EXAMPLE_COM);
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes.array()));
        assertThrows(IOException.class,
                () -> ListContent.copyNames(in, 2, new ByteArrayOutputStream()));
    }
}
