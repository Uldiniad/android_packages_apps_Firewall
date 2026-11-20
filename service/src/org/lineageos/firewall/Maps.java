/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.system.Os;

import java.io.FileDescriptor;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/** The firewall's eBPF map operations; tests substitute a fake. */
interface Maps {
    boolean init();
    /** Switches the BPF programs on; true if they are, or already were. */
    boolean attach();
    /**
     * Whether Connectivity's programs know whose socket an app reaches over loopback, as they do
     * from Linux 5.10 on, and so keep an app with no network left to itself.
     */
    boolean knowsLoopbackReceivers();
    void clearRules();
    int setUid(int uid, int rules);
    /** The slots of the specific networks the app is blocked or allowed on; 0s delete. */
    int setNamedNetworks(int uid, int block, int allow);
    /** The kinds of rules for all of the user's apps; 0 deletes. */
    int setUserFlags(int user, int flags);
    /** A network's bits: what blocks it, and the slot of the specific network it is. */
    int setIface(int ifindex, long net);
    int setNet(int netId, long net);
    void setVpnRanges(int[] starts, int[] ends, int[] netIds);
    /** Writes the limits under which rules name the range; 0 deletes. */
    int setIp(int scope, byte[] address, int prefixLength, boolean allow, int limits);
    /** Writes the domain's FirewallMaps.DOMAIN_* bits per limit for the scope; 0 deletes. */
    int setDomain(int scope, String domain, long bits);
    /**
     * Writes the FirewallMaps.PORT_* bits per limit for the ports that share the port's first
     * prefixLength bits; protocol 0 is both; 0 deletes.
     */
    int setPort(int scope, int protocol, int port, int prefixLength, int bits);
    /** The scope's network limits from limit 1 on, as network bits; empty deletes. */
    int setLimits(int scope, long[] only, long[] except);
    /** Drops the addresses learned from answers for the scope's allowed domains. */
    void forgetLearned(int scope);
    long[] counters();
    /** A descriptor that is readable when refusals are waiting; null without one. */
    FileDescriptor refusalsFd();
    /** The refusals reported since the last call, oldest first. */
    List<Refusal> consumeRefusals();
    /** Every count the BPF programs keep, also those that came after their last report. */
    List<Refusal> refusalStats();

    /** Where an app's refusals go: which way, and the far end. */
    record RefusalKey(int uid, int direction, int protocol, InetAddress address, int port) {}

    /**
     * An app's refusals to or from one far end: how many since the BPF programs first saw it, why
     * (FW_REFUSED_* bits), and the first and last as boot times.
     */
    record Refusal(RefusalKey key, long count, int reasons, long firstNanos, long lastNanos) {
        private static final int LONGS = 13;

        /** The refusals the JNI packs, LONGS each. */
        static List<Refusal> fromLongs(long[] values) {
            List<Refusal> refusals = new ArrayList<>();
            for (int i = 0; i + LONGS <= values.length; i += LONGS) {
                ByteBuffer bytes = ByteBuffer.allocate(16);
                for (int word = 0; word < 4; word++) bytes.putInt((int) values[i + 5 + word]);
                byte[] address = values[i + 3] != 0
                        ? bytes.array() : Arrays.copyOf(bytes.array(), 4);
                try {
                    refusals.add(new Refusal(new RefusalKey((int) values[i], (int) values[i + 1],
                            (int) values[i + 2], InetAddress.getByAddress(address),
                            (int) values[i + 4]), values[i + 9], (int) values[i + 10],
                            values[i + 11], values[i + 12]));
                } catch (UnknownHostException e) {
                    throw new AssertionError(e);
                }
            }
            return refusals;
        }
    }

    Maps NATIVE = new Maps() {
        @Override public boolean init() { return FirewallMaps.nativeInit(); }
        @Override public boolean attach() { return FirewallMaps.nativeAttach(); }
        @Override public boolean knowsLoopbackReceivers() {
            String[] version = Os.uname().release.split("[.-]", 3);
            int major = Integer.parseInt(version[0]);
            return major > 5 || (major == 5 && Integer.parseInt(version[1]) >= 10);
        }
        @Override public void clearRules() { FirewallMaps.nativeClearRules(); }
        @Override public int setUid(int uid, int rules) {
            return FirewallMaps.nativeSetUid(uid, rules);
        }
        @Override public int setNamedNetworks(int uid, int block, int allow) {
            return FirewallMaps.nativeSetNamedNetworks(uid, block, allow);
        }
        @Override public int setUserFlags(int user, int flags) {
            return FirewallMaps.nativeSetUserFlags(user, flags);
        }
        @Override public int setIface(int ifindex, long net) {
            return FirewallMaps.nativeSetIface(ifindex, net);
        }
        @Override public int setNet(int netId, long net) {
            return FirewallMaps.nativeSetNet(netId, net);
        }
        @Override public void setVpnRanges(int[] starts, int[] ends, int[] netIds) {
            FirewallMaps.nativeSetVpnRanges(starts, ends, netIds);
        }
        @Override public int setIp(int scope, byte[] address, int prefixLength, boolean allow,
                int limits) {
            return FirewallMaps.nativeSetIp(scope, address, prefixLength, allow, limits);
        }
        @Override public int setDomain(int scope, String domain, long bits) {
            return FirewallMaps.nativeSetDomain(scope, domain, bits);
        }
        @Override public int setLimits(int scope, long[] only, long[] except) {
            return FirewallMaps.nativeSetLimits(scope, only, except);
        }
        @Override public int setPort(int scope, int protocol, int port, int prefixLength,
                int bits) {
            return FirewallMaps.nativeSetPort(scope, protocol, port, prefixLength, bits);
        }
        @Override public void forgetLearned(int scope) {
            FirewallMaps.nativeForgetLearned(scope);
        }
        @Override public long[] counters() { return FirewallMaps.nativeCounters(); }
        @Override public FileDescriptor refusalsFd() { return FirewallMaps.nativeRefusalsFd(); }
        @Override public List<Refusal> consumeRefusals() {
            return Refusal.fromLongs(FirewallMaps.nativeConsumeRefusals());
        }
        @Override public List<Refusal> refusalStats() {
            return Refusal.fromLongs(FirewallMaps.nativeRefusalStats());
        }
    };

    /**
     * Adds a protocol's port ranges, each its first and last port and its bits, as the prefixes
     * the port map holds: keyed by port << 16 | prefix length << 8 | protocol, and split so they
     * don't overlap, as a port matches one prefix there. Each is valued with the bits of every
     * range covering it.
     */
    static void putPortPrefixes(Map<Long, Integer> ports, int protocol, List<int[]> ranges) {
        TreeSet<Integer> edges = new TreeSet<>();
        for (int[] range : ranges) {
            edges.add(range[0]);
            edges.add(range[1] + 1);
        }
        List<Integer> points = new ArrayList<>(edges);
        int start = 0;
        int startBits = 0;
        for (int i = 0; i < points.size(); i++) {
            int point = points.get(i);
            int bits = 0;
            for (int[] range : ranges) {
                if (range[0] <= point && point <= range[1]) bits |= range[2];
            }
            if (bits == startBits) continue;
            if (startBits != 0) putPrefixes(ports, protocol, start, point - 1, startBits);
            start = point;
            startBits = bits;
        }
    }

    private static void putPrefixes(Map<Long, Integer> ports, int protocol, int first, int last,
            int bits) {
        for (int port = first; port <= last; ) {
            int size = Integer.lowestOneBit(port);
            while (port + size - 1 > last) size >>= 1;
            int length = 16 - Integer.numberOfTrailingZeros(size);
            ports.put(((long) port << 16) | (length << 8) | protocol, bits);
            port += size;
        }
    }
}
