/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;


/** The firewall's BPF maps, which the BPF loader pins at boot. */
final class FirewallMaps {
    static final int BLOCK_ALL = IFirewall.BLOCK_ALL;
    static final int BLOCK_WIFI = IFirewall.BLOCK_WIFI;
    static final int BLOCK_CELLULAR = IFirewall.BLOCK_CELLULAR;
    static final int BLOCK_VPN = IFirewall.BLOCK_VPN;
    static final int BLOCK_OTHER = IFirewall.BLOCK_OTHER;
    static final int BLOCK_METERED = IFirewall.BLOCK_METERED;
    static final int BLOCK_ROAMING = IFirewall.BLOCK_ROAMING;
    /** The bits that block an app on a network, as a network's own bits say what it is. */
    static final int NETWORKS = BLOCK_WIFI | BLOCK_CELLULAR | BLOCK_VPN | BLOCK_OTHER
            | BLOCK_METERED | BLOCK_ROAMING;
    /** Set for apps with no network left that Connectivity can't keep to themselves. */
    static final int NO_LOOPBACK = 1 << 18;

    static final String[] COUNTERS = {
            "egress_drop_all",
            "egress_drop_transport",
            "ingress_drop",
            "connect_deny",
    };


    static {
        System.loadLibrary("firewall_jni");
    }

    private FirewallMaps() {}

    static native boolean nativeInit();
    static native boolean nativeAttach();
    static native void nativeClearRules();
    static native int nativeSetUid(int uid, int rules);
    static native int nativeSetIface(int ifindex, long net);
    static native int nativeSetNet(int netId, long net);
    static native void nativeSetVpnRanges(int[] starts, int[] ends, int[] netIds);
    static native long[] nativeCounters();
}
