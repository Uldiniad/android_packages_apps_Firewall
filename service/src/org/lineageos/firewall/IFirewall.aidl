/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import org.lineageos.firewall.AppRule;
import org.lineageos.firewall.FirewallRule;
import org.lineageos.firewall.IFirewallListener;
import org.lineageos.firewall.KnownNetwork;

interface IFirewall {
    /** Rule bits; each set bit blocks the app somewhere. */
    const int BLOCK_ALL = 1;
    const int BLOCK_WIFI = 2;
    const int BLOCK_CELLULAR = 4;
    const int BLOCK_VPN = 8;
    const int BLOCK_OTHER = 16;
    const int BLOCK_DNS = 32;
    /** Metered networks and roaming, whatever the transport; also while the app is in use. */
    const int BLOCK_METERED = 65536;
    const int BLOCK_ROAMING = 131072;

    /** An app's choice for a specific network: to follow the switch for its kind, or its own. */
    const int NETWORK_DEFAULT = 0;
    const int NETWORK_ALLOW = 1;
    const int NETWORK_BLOCK = 2;

    /** What a FirewallRule names. */
    const int RULE_ADDRESS = 0;
    const int RULE_DOMAIN = 1;
    const int RULE_PORT = 2;
    /** The protocols a port rule can be limited to; 0 is both. */
    const int PROTOCOL_TCP = 6;
    const int PROTOCOL_UDP = 17;

    void setAppRules(String packageName, int userId, int rules);
    /** Blocks the app, or allows it, until the time in milliseconds since the epoch; 0 ends it. */
    void setPause(String packageName, int userId, boolean block, long until);
    /**
     * Blocks the app each week on the days, as bits from Monday, from the start to the end minute
     * of the day, which is the next day's when before the start; no days clears it.
     */
    void setSchedule(String packageName, int userId, int days, int start, int end);
    int getAppRules(String packageName, int userId);
    AppRule[] getAppRulesForUser(int userId);

    /**
     * Sets the app's choice for a specific network, by its KnownNetwork key. False if rules and
     * choices already name as many specific networks as the firewall can tell apart.
     */
    boolean setAppNetwork(String packageName, int userId, String network, int choice);

    /** The user's specific networks: saved Wi-Fi networks, SIMs, VPN apps, and any rules name. */
    KnownNetwork[] getNetworks(int userId);
    /** The rules of one app, or with a null packageName those for all of the user's apps. */
    FirewallRule[] getRules(int userId, @nullable String packageName);
    /** Adds the rules; returns the positions of those it rejected, like a malformed address. */
    int[] addRules(in FirewallRule[] rules);
    void removeRules(in FirewallRule[] rules);
    void registerListener(IFirewallListener listener);
    void unregisterListener(IFirewallListener listener);
    /** Whether the firewall's programs are loaded and on; while not, apps aren't firewalled. */
    boolean isRunning();

    void setNewInstallsBlocked(int userId, boolean blocked);
    boolean areNewInstallsBlocked(int userId);
    byte[] getBackupPayload(int userId);
    void applyRestore(int userId, in byte[] payload);
}
