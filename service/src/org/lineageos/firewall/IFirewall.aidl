/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import org.lineageos.firewall.ActivityEntry;
import org.lineageos.firewall.AppRule;
import org.lineageos.firewall.FirewallGroup;
import org.lineageos.firewall.FirewallList;
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
    /** Connections others make to the app, by the port on the phone they arrive at. */
    const int RULE_INCOMING = 3;
    /** Who an incoming rule's connections come from, apart from an address or range. */
    const String INCOMING_FROM_ANYONE = "any";
    const String INCOMING_FROM_LOCAL_NETWORK = "local";
    /** The protocols a port rule can be limited to; 0 is both. */
    const int PROTOCOL_TCP = 6;
    const int PROTOCOL_UDP = 17;

    /** Why a list's last check failed; its last good content stays. */
    const int LIST_ERROR_NETWORK = 1;
    const int LIST_ERROR_SERVER = 2;
    const int LIST_ERROR_NOT_A_LIST = 3;
    const int LIST_ERROR_COUNT = 4;
    const int LIST_ERROR_STORAGE = 5;
    const int LIST_ERROR_MEMORY = 6;
    const int LIST_ERROR_FULL = 7;

    /** A group goes by this and its id where calls take an app's packageName, for its rules. */
    const String GROUP_PREFIX = "group:";

    /** The devices on the phone's hotspot go by this for their rules, in the main user. */
    const String HOTSPOT_PACKAGE = "hotspot:devices";

    /** What an ActivityEntry is: a connection, traffic out or in, one others opened, a lookup. */
    const int ACTIVITY_CONNECT = 0;
    const int ACTIVITY_OUT = 1;
    const int ACTIVITY_IN = 2;
    const int ACTIVITY_INCOMING = 3;
    const int ACTIVITY_LOOKUP = 4;
    /**
     * Why something was refused, as bits: the app blocked everywhere or on the network, its
     * address, port, own DNS, local network through a VPN, list or domain rules, or its incoming
     * rules; those for all apps apart.
     */
    const int REASON_ALL = 1;
    const int REASON_NETWORK = 2;
    const int REASON_ADDRESS = 4;
    const int REASON_PORT = 8;
    const int REASON_DNS = 16;
    const int REASON_USER_ADDRESS = 32;
    const int REASON_USER_PORT = 64;
    const int REASON_USER_DNS = 128;
    const int REASON_LAN = 256;
    const int REASON_LIST = 512;
    const int REASON_USER_LIST = 1024;
    const int REASON_DOMAIN = 2048;
    const int REASON_USER_DOMAIN = 4096;
    const int REASON_INCOMING = 8192;
    const int REASON_USER_INCOMING = 16384;

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

    /** The user's lists, for all of their apps and for each app. */
    FirewallList[] getLists(int userId);
    /**
     * Subscribes the app, or with a null packageName all of the user's apps, to the list at the
     * https address; its id, or null when the firewall holds as many lists as it can.
     */
    @nullable String addList(int userId, @nullable String packageName, String url,
            boolean subdomains);
    /** Adds a list read from a file, with content as setListContent takes it; as addList. */
    @nullable String addListFromFile(int userId, @nullable String packageName, String title,
            in ParcelFileDescriptor content);
    void removeList(int userId, @nullable String packageName, String id);
    /**
     * Replaces the list's content with what the firewall app read from a download, in the
     * form ListContent writes, with what the download said of itself; 0 or a LIST_ERROR_*.
     */
    int setListContent(String id, in ParcelFileDescriptor content, @nullable String title,
            @nullable String version, @nullable String etag, @nullable String lastModified);
    /** A check that left the content as it was: unchanged with error 0, else failed. */
    void setListChecked(String id, int error, int errorDetail);

    /** Turns the firewall on or off for the whole phone, which only an admin user can. */
    void setEnabled(boolean enabled);
    /** Whether the firewall is on; while it's off, no rules apply, though they can change. */
    boolean isEnabled();

    /** The user's groups of apps, which follow their group's rules instead of their own. */
    FirewallGroup[] getGroups(int userId);
    /** Adds a group with no apps and no rules, so it allows everything; its id. */
    String addGroup(int userId, String name);
    void renameGroup(int userId, String id, String name);
    /** Removes the group; its apps keep a copy of its rules as their own. */
    void removeGroup(int userId, String id);
    /**
     * Puts the app, with those sharing its uid, in the group, whose rules replace their own; with
     * a null id takes them out, leaving them a copy of the group's rules as their own.
     */
    void setAppGroup(String packageName, int userId, @nullable String id);

    /** Turns the user's activity log on or off; off stops recording, and keeps what's there. */
    void setActivityLog(int userId, boolean on);
    boolean isActivityLogOn(int userId);
    /** The user's new entries, which the firewall app keeps from then on. */
    ActivityEntry[] takeActivity(int userId);
    /** Drops the user's entries the firewall app hasn't taken yet. */
    void clearActivity(int userId);
}
