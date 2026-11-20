/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.os.SystemProperties;
import android.system.Os;

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
    Maps NATIVE = new Maps() {
        @Override public boolean init() { return FirewallMaps.nativeInit(); }
        @Override public boolean attach() { return FirewallMaps.nativeAttach(); }
        @Override public boolean knowsLoopbackReceivers() {
            // The version Connectivity goes by, which LineageOS lets a kernel with backports raise.
            String release = SystemProperties.get("ro.bpf.kver_override", Os.uname().release);
            String[] version = release.split("[.-]", 3);
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
    };
}
