/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

/**
 * An entry of a user's activity log: what an app sent or received, or a lookup the firewall
 * refused, with repeats counted in it.
 */
parcelable ActivityEntry {
    /** The same each time the entry comes again with a later time and count, as it goes on. */
    String key;
    int uid;
    /** IFirewall.ACTIVITY_*: which way the traffic went, or a lookup. */
    int kind;
    /** IPPROTO_TCP, IPPROTO_UDP or another IP protocol; 0 for a lookup. */
    int protocol;
    /** The far end, or for incoming traffic the sender; null for a lookup. */
    @nullable String address;
    /** The far end's port, or for incoming traffic the port on the phone. */
    int port;
    /** The name the app looked up for the address, or that of a lookup. */
    @nullable String name;
    boolean allowed;
    /** For what was refused, IFirewall.REASON_* bits: every rule that refused it. */
    int reasons;
    /** IFirewall.BLOCK_WIFI, BLOCK_CELLULAR, BLOCK_VPN or BLOCK_OTHER; 0 when it isn't known. */
    int network;
    long firstMillis;
    long lastMillis;
    long count;
    long bytes;
}
