/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.net.InetAddresses;
import android.net.IpPrefix;
import android.os.Process;
import android.os.UserHandle;
import android.util.Pair;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.nio.ByteOrder;
import java.nio.LongBuffer;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Which of the current rules, lists and switches account for a refused activity entry, worked
 * out from the reasons the programs reported when its page opens, as Firewalla's Diagnose does.
 */
final class Diagnose {
    /** Each kind of rule's reason for a level's own rules, then for the rules for all apps. */
    private static final int[][] RULE_REASONS = {
            {IFirewall.REASON_INCOMING, IFirewall.REASON_USER_INCOMING},
            {IFirewall.REASON_DOMAIN, IFirewall.REASON_USER_DOMAIN},
            {IFirewall.REASON_LIST, IFirewall.REASON_USER_LIST},
            {IFirewall.REASON_ADDRESS, IFirewall.REASON_USER_ADDRESS},
            {IFirewall.REASON_PORT, IFirewall.REASON_USER_PORT},
            {IFirewall.REASON_DNS, IFirewall.REASON_USER_DNS},
    };
    private static final int[] SWITCH_REASONS = {IFirewall.REASON_LAN, IFirewall.REASON_NETWORK,
            IFirewall.REASON_LOCKED, IFirewall.REASON_ALL};

    private Diagnose() {}

    /** A level's block rules and lists; a null package name is the rules for all apps. */
    private record Level(String packageName, List<FirewallRule> blocks, List<Listed> lists) {}

    private record Listed(String title, File names, List<IpPrefix> ranges) {}

    static ActivityMatch[] explain(FirewallService service, int userId, ActivityEntry entry) {
        List<Level> own = new ArrayList<>();
        Level all;
        synchronized (service) {
            boolean hotspot = isHotspotUid(entry.uid);
            int ownUser = hotspot ? UserHandle.USER_SYSTEM : userId;
            for (String packageName : ownLevelsLocked(service, userId, entry.uid)) {
                own.add(levelLocked(service, packageName, ownUser));
            }
            all = levelLocked(service, null, hotspot ? UserHandle.USER_SYSTEM : userId);
        }
        InetAddress address = parseAddress(entry.address);
        String name = parseName(entry.name);
        String ownPackage = own.isEmpty() ? null : own.get(0).packageName();
        List<ActivityMatch> matches = new ArrayList<>();
        for (int[] reasons : RULE_REASONS) {
            if ((entry.reasons & reasons[0]) != 0) {
                addMatches(matches, reasons[0], own, ownPackage, entry, name, address);
            }
            if ((entry.reasons & reasons[1]) != 0) {
                addMatches(matches, reasons[1], List.of(all), null, entry, name, address);
            }
        }
        for (int reason : SWITCH_REASONS) {
            if ((entry.reasons & reason) != 0) matches.add(match(reason, ownPackage, null, null));
        }
        if ((entry.reasons & IFirewall.REASON_USER_LOCKED) != 0) {
            matches.add(match(IFirewall.REASON_USER_LOCKED, null, null, null));
        }
        if ((entry.reasons & IFirewall.REASON_LOCKDOWN) != 0) {
            matches.add(0, match(IFirewall.REASON_LOCKDOWN, null, null, null));
        }
        return matches.toArray(new ActivityMatch[0]);
    }

    private static boolean isHotspotUid(int uid) {
        return Hotspot.isDeviceUid(uid) || UserHandle.getAppId(uid) == Process.DNS_TETHER_UID;
    }

    /** The levels whose own rules apply to the uid, the most specific first. */
    private static List<String> ownLevelsLocked(FirewallService service, int userId, int uid) {
        Hotspot hotspot = service.feature(Hotspot.class);
        if (Hotspot.isDeviceUid(uid) && hotspot != null) {
            for (Map.Entry<String, Integer> device : hotspot.deviceUids.entrySet()) {
                if (device.getValue() == uid) {
                    return List.of(IFirewall.DEVICE_PREFIX + device.getKey(),
                            IFirewall.HOTSPOT_PACKAGE);
                }
            }
            return List.of(IFirewall.HOTSPOT_PACKAGE);
        }
        if (UserHandle.getAppId(uid) == Process.DNS_TETHER_UID) {
            return List.of(IFirewall.HOTSPOT_PACKAGE);
        }
        String[] packages = service.context().getPackageManager().getPackagesForUid(uid);
        if (packages == null || packages.length == 0) return List.of();
        Groups groups = service.feature(Groups.class);
        Pair<String, Integer> group =
                groups != null ? groups.groupOfLocked(Pair.create(packages[0], userId)) : null;
        return List.of(group != null ? group.first : packages[0]);
    }

    private static Level levelLocked(FirewallService service, String packageName, int userId) {
        List<FirewallRule> blocks = new ArrayList<>();
        TargetRules rules = service.feature(TargetRules.class);
        if (rules != null) {
            for (FirewallRule rule : rules.getRulesInternal(userId, packageName)) {
                if (!rule.allow) blocks.add(rule);
            }
        }
        List<Listed> listed = new ArrayList<>();
        BlockLists lists = service.feature(BlockLists.class);
        if (lists != null) {
            Set<String> ids = packageName == null ? lists.userLists.get(userId)
                    : lists.appLists.get(Pair.create(packageName, userId));
            for (String id : ids != null ? ids : Set.<String>of()) {
                BlockLists.BlockList list = lists.lists.get(id);
                if (list == null) continue;
                listed.add(new Listed(list.title != null ? list.title : list.url,
                        list.generation != 0 ? lists.namesFile(list.slot, list.generation) : null,
                        list.ranges));
            }
        }
        return new Level(packageName, blocks, listed);
    }

    /**
     * Adds what accounts for the reason in the levels, or one match without a rule or list when
     * nothing does any more: the rule changed since, or a name the answer pointed to matched.
     */
    private static void addMatches(List<ActivityMatch> matches, int reason, List<Level> levels,
            String fallbackPackage, ActivityEntry entry, String name, InetAddress address) {
        int before = matches.size();
        for (Level level : levels) {
            switch (reason) {
                case IFirewall.REASON_DOMAIN, IFirewall.REASON_USER_DOMAIN -> {
                    if (name == null) break;
                    for (FirewallRule rule : level.blocks()) {
                        if (rule.kind == IFirewall.RULE_DOMAIN && domainCovers(rule, name)
                                && portCovers(rule.port, rule.protocol, entry)) {
                            matches.add(match(reason, level.packageName(), rule, null));
                        }
                    }
                    for (Listed list : level.lists()) {
                        if (namesHold(list.names(), name)) {
                            matches.add(match(reason, level.packageName(), null, list.title()));
                        }
                    }
                }
                case IFirewall.REASON_LIST, IFirewall.REASON_USER_LIST -> {
                    if (address == null) break;
                    for (Listed list : level.lists()) {
                        if (list.ranges().stream().anyMatch(range -> range.contains(address))) {
                            matches.add(match(reason, level.packageName(), null, list.title()));
                        }
                    }
                }
                case IFirewall.REASON_ADDRESS, IFirewall.REASON_USER_ADDRESS -> {
                    for (FirewallRule rule : level.blocks()) {
                        if (rule.kind == IFirewall.RULE_ADDRESS
                                && prefixCovers(rule.value, address)
                                && portCovers(rule.port, rule.protocol, entry)) {
                            matches.add(match(reason, level.packageName(), rule, null));
                        }
                    }
                }
                case IFirewall.REASON_PORT, IFirewall.REASON_USER_PORT -> {
                    for (FirewallRule rule : level.blocks()) {
                        if (rule.kind == IFirewall.RULE_PORT
                                && portCovers(rule.value, rule.protocol, entry)) {
                            matches.add(match(reason, level.packageName(), rule, null));
                        }
                    }
                }
                case IFirewall.REASON_INCOMING, IFirewall.REASON_USER_INCOMING -> {
                    for (FirewallRule rule : level.blocks()) {
                        if (rule.kind == IFirewall.RULE_INCOMING
                                && senderCovers(rule.value, address)
                                && portCovers(rule.port, rule.protocol, entry)) {
                            matches.add(match(reason, level.packageName(), rule, null));
                        }
                    }
                }
                default -> {}
            }
        }
        if (matches.size() == before) {
            String packageName = levels.isEmpty() ? fallbackPackage : levels.get(0).packageName();
            matches.add(match(reason, packageName, null, null));
        }
    }

    private static ActivityMatch match(int reason, String packageName, FirewallRule rule,
            String list) {
        ActivityMatch match = new ActivityMatch();
        match.reason = reason;
        match.packageName = packageName;
        match.rule = rule;
        match.list = list;
        return match;
    }

    private static InetAddress parseAddress(String address) {
        if (address == null) return null;
        try {
            return InetAddresses.parseNumericAddress(address);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static String parseName(String name) {
        if (name == null) return null;
        try {
            return Names.normalizeDomain(name);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static boolean domainCovers(FirewallRule rule, String name) {
        return name.equals(rule.value) || (rule.subdomains && name.endsWith("." + rule.value));
    }

    /** Whether the rule's port and protocol, when it names a port, cover the entry's. */
    private static boolean portCovers(String port, int protocol, ActivityEntry entry) {
        if (port == null) return true;
        if (protocol != 0 && protocol != entry.protocol) return false;
        int[] range = TargetRule.portRange(port);
        return entry.port >= range[0] && entry.port <= range[1];
    }

    private static boolean prefixCovers(String prefix, InetAddress address) {
        return address != null && Names.parsePrefix(prefix).contains(address);
    }

    private static boolean senderCovers(String sender, InetAddress address) {
        if (sender.equals(IFirewall.INCOMING_FROM_ANYONE)) return true;
        if (sender.equals(IFirewall.INCOMING_FROM_LOCAL_NETWORK)) {
            return address != null && (address.isSiteLocalAddress()
                    || address.isLinkLocalAddress()
                    || (address instanceof Inet6Address
                            && (address.getAddress()[0] & 0xfe) == 0xfc));
        }
        return prefixCovers(sender, address);
    }

    /**
     * Whether a list's names file holds the name, or a domain above it that covers subdomains, as
     * netd's lookup check searches it: a header, then keys sorted as signed numbers.
     */
    private static boolean namesHold(File names, String name) {
        if (names == null) return false;
        try (RandomAccessFile file = new RandomAccessFile(names, "r");
                FileChannel channel = file.getChannel()) {
            LongBuffer keys = channel.map(FileChannel.MapMode.READ_ONLY, 0, channel.size())
                    .order(ByteOrder.LITTLE_ENDIAN).asLongBuffer();
            int count = (int) Math.min(keys.get(1), keys.capacity() - 2L);
            if (holds(keys, count, ListContent.nameKey(name, false))
                    || holds(keys, count, ListContent.nameKey(name, true))) {
                return true;
            }
            for (int dot = name.indexOf('.'); dot >= 0; dot = name.indexOf('.', dot + 1)) {
                if (holds(keys, count, ListContent.nameKey(name.substring(dot + 1), true))) {
                    return true;
                }
            }
            return false;
        } catch (IOException e) {
            return false;
        }
    }

    private static boolean holds(LongBuffer keys, int count, long key) {
        int low = 0;
        int high = count - 1;
        while (low <= high) {
            int middle = (low + high) >>> 1;
            long value = keys.get(2 + middle);
            if (value < key) {
                low = middle + 1;
            } else if (value > key) {
                high = middle - 1;
            } else {
                return true;
            }
        }
        return false;
    }
}
