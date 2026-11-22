/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.net.IpPrefix;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * A list's entries as the firewall keeps them: each domain as the key netd's lookup check looks
 * for, and each address range. The firewall app reads a download into this and hands it to the
 * service as write() puts it, little-endian: a header, the sorted keys, then the ranges.
 */
final class ListContent {
    static final int MAGIC = 0x314c5746;
    /** Starts the file of keys that netd maps, as FW_LIST_NAMES_MAGIC. */
    static final long NAMES_MAGIC = 0x3153454d414e4c46L;
    static final int HEADER_BYTES = 16;
    static final int RANGE_BYTES = 18;
    private static final long FNV_OFFSET = 0xcbf29ce484222325L;
    private static final long FNV_PRIME = 0x100000001b3L;
    private static final int CHUNK = 8192;

    /** Sorted as signed numbers, as netd searches them, and distinct. */
    final long[] names;
    final List<IpPrefix> ranges;

    ListContent(long[] names, List<IpPrefix> ranges) {
        this.names = names;
        this.ranges = ranges;
    }

    /**
     * The hash netd's lookup check gives a domain, from its labels' hashes from the top-level
     * domain down, with the lowest bit set when the entry covers the domain's subdomains too.
     */
    static long nameKey(String domain, boolean subdomains) {
        long suffix = FNV_OFFSET;
        String[] labels = domain.split("\\.");
        for (int i = labels.length - 1; i >= 0; i--) {
            if (labels[i].isEmpty()) continue;
            long label = FNV_OFFSET;
            for (byte b : labels[i].getBytes(StandardCharsets.US_ASCII)) {
                label = (label ^ (b & 0xff)) * FNV_PRIME;
            }
            suffix = (suffix ^ label) * FNV_PRIME;
        }
        return (suffix & ~1L) | (subdomains ? 1 : 0);
    }

    long size() {
        return HEADER_BYTES + 8L * names.length + (long) RANGE_BYTES * ranges.size();
    }

    void write(OutputStream out) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(CHUNK * 8).order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(MAGIC).putInt(ranges.size()).putLong(names.length);
        for (long name : names) {
            if (!buffer.hasRemaining()) flush(buffer, out);
            buffer.putLong(name);
        }
        for (IpPrefix range : ranges) {
            if (buffer.remaining() < RANGE_BYTES) flush(buffer, out);
            byte[] address = range.getRawAddress();
            buffer.put((byte) (address.length == 4 ? 4 : 6)).put((byte) range.getPrefixLength());
            buffer.put(Arrays.copyOf(address, 16));
        }
        flush(buffer, out);
    }

    private static void flush(ByteBuffer buffer, OutputStream out) throws IOException {
        out.write(buffer.array(), 0, buffer.position());
        buffer.clear();
    }

    /** Collects what the parser reads; build() sorts it. */
    static final class Builder implements ListParser.Entries {
        private long[] mNames = new long[CHUNK];
        private int mCount;
        private final Set<IpPrefix> mRanges = new LinkedHashSet<>();

        @Override
        public void domain(String name, boolean subdomains) {
            if (mCount == mNames.length) mNames = Arrays.copyOf(mNames, mCount * 2);
            mNames[mCount++] = nameKey(name, subdomains);
        }

        @Override
        public void prefix(IpPrefix prefix) {
            mRanges.add(prefix);
        }

        /** The entries, each name once: an entry for its subdomains covers the name itself. */
        ListContent build() {
            Arrays.sort(mNames, 0, mCount);
            int kept = 0;
            for (int i = 0; i < mCount; i++) {
                long key = mNames[i];
                if (kept > 0 && mNames[kept - 1] == key) continue;
                if (kept > 0 && (key & 1) == 1 && mNames[kept - 1] == (key & ~1L)) {
                    mNames[kept - 1] = key;
                    continue;
                }
                mNames[kept++] = key;
            }
            return new ListContent(Arrays.copyOf(mNames, kept), new ArrayList<>(mRanges));
        }
    }

    /** What write() starts with: how many ranges and names follow. */
    record Header(int ranges, long names) {
        static Header read(DataInputStream in) throws IOException {
            ByteBuffer header = ByteBuffer.allocate(HEADER_BYTES).order(ByteOrder.LITTLE_ENDIAN);
            in.readFully(header.array());
            if (header.getInt() != MAGIC) throw new IOException("Not list content");
            int ranges = header.getInt();
            long names = header.getLong();
            if (ranges < 0 || names < 0) throw new IOException("Bad counts");
            return new Header(ranges, names);
        }
    }

    /**
     * Copies the keys that follow the header to out, as netd's file holds them after its own
     * header, and checks that they are sorted and distinct, as netd's search needs.
     */
    static void copyNames(DataInputStream in, long count, OutputStream out) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(CHUNK * 8).order(ByteOrder.LITTLE_ENDIAN);
        buffer.putLong(NAMES_MAGIC).putLong(count);
        flush(buffer, out);
        long previous = Long.MIN_VALUE;
        for (long left = count; left > 0; ) {
            int n = (int) Math.min(left, CHUNK);
            in.readFully(buffer.array(), 0, n * 8);
            for (int i = 0; i < n; i++) {
                long key = buffer.getLong(i * 8);
                if ((left != count || i > 0) && key <= previous) {
                    throw new IOException("Names out of order");
                }
                previous = key;
            }
            out.write(buffer.array(), 0, n * 8);
            left -= n;
        }
    }

    /** Reads the ranges that follow the keys. */
    static List<IpPrefix> readRanges(DataInputStream in, int count) throws IOException {
        List<IpPrefix> ranges = new ArrayList<>();
        byte[] record = new byte[RANGE_BYTES];
        for (int i = 0; i < count; i++) {
            in.readFully(record);
            int length = record[0] == 4 ? 4 : record[0] == 6 ? 16 : -1;
            if (length < 0) throw new IOException("Bad range");
            byte[] address = Arrays.copyOfRange(record, 2, 2 + length);
            try {
                ranges.add(new IpPrefix(InetAddress.getByAddress(address), record[1] & 0xff));
            } catch (UnknownHostException | IllegalArgumentException e) {
                throw new IOException("Bad range", e);
            }
        }
        return ranges;
    }
}
