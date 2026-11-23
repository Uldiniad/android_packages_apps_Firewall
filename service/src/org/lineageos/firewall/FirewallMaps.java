/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import java.io.FileDescriptor;

/** The firewall's BPF maps, which the BPF loader pins at boot. */
final class FirewallMaps {
    static final int BLOCK_ALL = IFirewall.BLOCK_ALL;
    static final int BLOCK_WIFI = IFirewall.BLOCK_WIFI;
    static final int BLOCK_CELLULAR = IFirewall.BLOCK_CELLULAR;
    static final int BLOCK_VPN = IFirewall.BLOCK_VPN;
    static final int BLOCK_OTHER = IFirewall.BLOCK_OTHER;
    static final int BLOCK_DNS = IFirewall.BLOCK_DNS;
    static final int BLOCK_METERED = IFirewall.BLOCK_METERED;
    static final int BLOCK_ROAMING = IFirewall.BLOCK_ROAMING;
    /** The bits that block an app on a network, as a network's own bits say what it is. */
    static final int NETWORKS = BLOCK_WIFI | BLOCK_CELLULAR | BLOCK_VPN | BLOCK_OTHER
            | BLOCK_METERED | BLOCK_ROAMING;
    /** Set for apps without ACCESS_LOCAL_NETWORK, to keep them off the LAN through VPNs. */
    static final int NO_LAN = 1 << 6;
    /** Set for apps with choices for specific networks. */
    static final int NAMED_NETWORKS = 1 << 7;
    /** Set for apps with no network left that Connectivity can't keep to themselves. */
    static final int NO_LOOPBACK = 1 << 18;
    /** Set for the firewall app, which lists never cover. */
    static final int NO_LISTS = 1 << 19;
    static final int LAN_LOCAL = 1;
    static final int LAN_DNS = 2;

    /** The scope of the rules for all of a user's apps; an app's scope is its uid. */
    static final int USER_SCOPE = 1 << 31;
    /** Known DNS-over-HTTPS servers, as the programs' FW_DOH_SCOPE. */
    static final int DOH_SCOPE = USER_SCOPE | 0x7fffffff;
    /** The kinds of rules a scope has, kept with an app's rules and per user. */
    static final int SCOPE_IP_BLOCKS = 1 << 8;
    static final int SCOPE_IP_ALLOWS = 1 << 9;
    static final int SCOPE_PORT_BLOCKS = 1 << 10;
    static final int SCOPE_PORT_ALLOWS = 1 << 11;
    static final int SCOPE_DOMAINS = 1 << 12;
    static final int SCOPE_LEARNED = 1 << 13;
    /** Some of the scope's rules are limited to networks. */
    static final int SCOPE_LIMITS = 1 << 14;
    /** The scope subscribes to lists, by the bits of their slots. */
    static final int SCOPE_LISTS = 1 << 15;
    /** The scope blocks domains on a port, whose answers' addresses are learned for that port. */
    static final int SCOPE_LEARNED_BLOCKS = 1 << 20;
    /** The scope has rules for connections others open to its apps, in its incoming scope. */
    static final int SCOPE_INCOMING_BLOCKS = 1 << 21;
    static final int SCOPE_INCOMING_ALLOWS = 1 << 22;
    static final int SCOPE_INCOMING = SCOPE_INCOMING_BLOCKS | SCOPE_INCOMING_ALLOWS;
    /** A scope with this set holds the incoming rules of the scope without it. */
    static final int INCOMING_SCOPE = 1 << 30;
    static final int LIST_SLOTS = 64;
    static final int SCOPE_ALLOWS = SCOPE_IP_ALLOWS | SCOPE_PORT_ALLOWS | SCOPE_LEARNED
            | SCOPE_INCOMING_ALLOWS;
    /** A domain matches its own bits; a parent domain matches only its subdomain bits. */
    static final int DOMAIN_BLOCK = 1;
    static final int DOMAIN_BLOCK_SUBDOMAINS = 1 << 1;
    static final int DOMAIN_ALLOW = 1 << 2;
    static final int DOMAIN_ALLOW_SUBDOMAINS = 1 << 3;
    static final int PORT_BLOCK = 1;
    static final int PORT_ALLOW = 1 << 1;
    /** Specific networks take a slot in the high word of network bits. */
    static final int SLOTS = 32;
    /** Limit 0 is every network; rule entries hold bits for each limit. */
    static final int LIMITS = 16;
    /** The ports of a scope's limits are port entries under the scope with this set. */
    static final int LIMIT_PORTS_SCOPE = 1 << 29;

    static final String[] COUNTERS = {
            "egress_drop_all",
            "egress_drop_transport",
            "egress_drop_ip",
            "egress_drop_dns",
            "ingress_drop",
            "connect_deny",
            "dns_seen",
            "egress_drop_domain",
            "egress_drop_lan",
            "egress_drop_port",
            "allowed_by_rule",
            "egress_drop_list",
    };
    /** Names of the FW_REFUSED_* bits, and of the FW_REFUSAL_* directions. */
    static final String[] REFUSAL_REASONS = {
            "all",
            "network",
            "address",
            "port",
            "dns",
            "address for all apps",
            "port for all apps",
            "dns for all apps",
            "lan",
            "list",
            "list for all apps",
            "domain",
            "domain for all apps",
            "incoming",
            "incoming for all apps",
    };
    /** The FW_REFUSED_* bits, the most specific reason first. */
    static final int[] REFUSAL_REASON_ORDER = {
            2, 3, 5, 6, 4, 7,
            11, 12,
            13, 14,
            9, 10,
            8,
            1, 0,
    };
    static final String[] REFUSAL_DIRECTIONS = {"connect", "out", "in", "incoming"};


    static {
        System.loadLibrary("firewall_jni");
    }

    private FirewallMaps() {}

    static native boolean nativeInit();
    static native boolean nativeAttach();
    static native boolean nativeDetach();
    static native void nativeClearRules();
    static native int nativeSetUid(int uid, int rules);
    static native int nativeSetNamedNetworks(int uid, int block, int allow);
    static native int nativeSetUserFlags(int user, int flags);
    static native int nativeSetIface(int ifindex, long net);
    static native int nativeSetNet(int netId, long net);
    static native void nativeSetVpnRanges(int[] starts, int[] ends, int[] netIds);
    static native int nativeSetIp(int scope, byte[] address, int prefixLength, boolean allow,
            int limits);
    static native int nativeSetLan(byte[] address, int prefixLength, int kind);
    static native int nativeSetDomain(int scope, String domain, long bits);
    static native int nativeSetLimits(int scope, long[] only, long[] except, int ported,
            int localNetwork);
    static native int nativeSetPort(int scope, int protocol, int port, int prefixLength,
            int bits);
    static native void nativeForgetLearned(int scope);
    static native int nativeSetScopeLists(int scope, long slots);
    static native int nativeSetListRange(byte[] address, int prefixLength, long slots);
    static native int nativeSetListFile(int slot, int generation);
    static native long[] nativeCounters();
    static native FileDescriptor nativeRefusalsFd();
    static native long[] nativeConsumeRefusals();
    static native long[] nativeRefusalStats();
}
