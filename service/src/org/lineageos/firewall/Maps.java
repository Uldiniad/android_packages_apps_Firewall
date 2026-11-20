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
    /** A network's bits: what blocks it. */
    int setIface(int ifindex, long net);
    int setNet(int netId, long net);
    void setVpnRanges(int[] starts, int[] ends, int[] netIds);
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
        @Override public int setIface(int ifindex, long net) {
            return FirewallMaps.nativeSetIface(ifindex, net);
        }
        @Override public int setNet(int netId, long net) {
            return FirewallMaps.nativeSetNet(netId, net);
        }
        @Override public void setVpnRanges(int[] starts, int[] ends, int[] netIds) {
            FirewallMaps.nativeSetVpnRanges(starts, ends, netIds);
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
}
