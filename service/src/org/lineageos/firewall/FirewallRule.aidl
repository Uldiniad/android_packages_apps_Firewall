/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

/**
 * A rule blocking or allowing an address range, a domain or a remote port: for one app, or for
 * all of the user's apps when packageName is null. An app's rules come before those for all
 * apps, and an allow rule wins over a block rule for the same apps.
 */
parcelable FirewallRule {
    @nullable String packageName;
    int userId;
    boolean allow;
    /** IFirewall.RULE_ADDRESS, RULE_DOMAIN or RULE_PORT. */
    int kind;
    /** An address or range like 192.0.2.0/24, a domain, or a port number. */
    String value;
    /** For domains, whether the rule also covers their subdomains. */
    boolean subdomains;
    /** For ports, IFirewall.PROTOCOL_TCP or PROTOCOL_UDP, or 0 for both. */
    int protocol;
    /** The networks the rule is limited to, by key, like "wifi"; without any, every network. */
    @nullable String[] networks;
    /** Whether the rule applies on every network but those, rather than only on them. */
    boolean exceptNetworks;
}
