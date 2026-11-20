/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.net.InetAddresses;
import android.net.IpPrefix;
import android.os.Environment;
import android.os.UserHandle;
import android.util.Log;
import android.util.Pair;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlSerializer;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.Inet4Address;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Predicate;

/**
 * Rules that block or allow an address, a domain or a port, for one app or for all of a user's
 * apps, everywhere or only on some networks. Each scope's rules become entries in the address,
 * port and domain maps, under numbered limits of the networks they apply on.
 */
final class TargetRules extends Feature {
    private static final File DOH_SERVERS =
            new File(Environment.getRootDirectory(), "etc/firewall/doh-servers.txt");

    /** Rules for all of a user's apps, and for one app, by (package name, user id). */
    final Map<Integer, Set<TargetRule>> userTargets = new HashMap<>();
    final Map<Pair<String, Integer>, Set<TargetRule>> appTargets = new HashMap<>();
    /** What the maps hold for each scope's rules, so only changes get written. */
    private final Map<Integer, ScopeEntries> mScopeEntries = new HashMap<>();

    TargetRules(FirewallService service) {
        super(service);
    }

    @Override
    void clearStore() {
        userTargets.clear();
        appTargets.clear();
    }

    @Override
    boolean readStoreTag(XmlPullParser parser) throws IOException, XmlPullParserException {
        if (!"rule".equals(parser.getName())) return false;
        int user = Integer.parseInt(parser.getAttributeValue(null, "user"));
        String packageName = parser.getAttributeValue(null, "package");
        try {
            TargetRule rule = TargetRule.read(parser);
            (packageName == null
                    ? userTargets.computeIfAbsent(user, u -> new TreeSet<>())
                    : appTargets.computeIfAbsent(Pair.create(packageName, user),
                            app -> new TreeSet<>())).add(rule);
        } catch (IllegalArgumentException e) {
            Log.w(FirewallService.TAG, "Skipped a malformed rule");
        }
        return true;
    }

    @Override
    void writeStore(XmlSerializer serializer) throws IOException {
        for (Map.Entry<Integer, Set<TargetRule>> user : userTargets.entrySet()) {
            for (TargetRule rule : user.getValue()) rule.write(serializer, user.getKey(), null);
        }
        for (Map.Entry<Pair<String, Integer>, Set<TargetRule>> app : appTargets.entrySet()) {
            for (TargetRule rule : app.getValue()) {
                rule.write(serializer, app.getKey().second, app.getKey().first);
            }
        }
    }

    /** An app's or a user's rules as backed up. */
    private record Part(Set<TargetRule> rules) {}

    private static Part partOf(Set<TargetRule> rules) {
        return rules == null || rules.isEmpty() ? null : new Part(new TreeSet<>(rules));
    }

    @Override
    Object backupAppLocked(Pair<String, Integer> app) {
        return partOf(appTargets.get(app));
    }

    @Override
    Object backupUserLocked(int userId) {
        return partOf(userTargets.get(userId));
    }

    @Override
    void writeBackupTags(Object part, boolean user, XmlSerializer serializer) throws IOException {
        for (TargetRule rule : ((Part) part).rules()) rule.write(serializer, null, null);
    }

    @Override
    boolean readBackupTag(XmlPullParser parser, boolean user, FirewallBackup.Parts parts)
            throws IOException, XmlPullParserException {
        if (!"rule".equals(parser.getName())) return false;
        Part part = (Part) parts.get(this);
        if (part == null) {
            part = new Part(new TreeSet<>());
            parts.put(this, part);
        }
        try {
            part.rules().add(TargetRule.read(parser));
        } catch (IllegalArgumentException e) {
            // Skipped.
        }
        return true;
    }

    @Override
    void restoreAppLocked(Pair<String, Integer> app, FirewallBackup.App restored) {
        Part part = (Part) restored.parts().get(this);
        if (part == null || part.rules().isEmpty()) {
            appTargets.remove(app);
        } else {
            appTargets.put(app, new TreeSet<>(part.rules()));
        }
    }

    @Override
    void restoreUserLocked(int userId, Object part) {
        if (part instanceof Part rules && !rules.rules().isEmpty()) {
            userTargets.put(userId, new TreeSet<>(rules.rules()));
        }
    }

    @Override
    void onLoadedLocked(Set<Integer> users) {
        userTargets.keySet().retainAll(users);
        appTargets.keySet().removeIf(app ->
                !users.contains(app.second) || mService.knownUid(app) < 0);
    }

    @Override
    void onMapsClearedLocked() {
        mScopeEntries.clear();
        writeDohServersLocked();
    }

    @Override
    void onStartSyncedLocked() {
        for (int user : List.copyOf(userTargets.keySet())) mService.syncUserLocked(user);
    }

    @Override
    boolean forgetAppsLocked(Predicate<Pair<String, Integer>> gone) {
        return appTargets.keySet().removeIf(gone);
    }

    @Override
    boolean forgetUserLocked(int userId) {
        boolean changed = appTargets.keySet().removeIf(app -> app.second == userId);
        return userTargets.remove(userId) != null || changed;
    }

    @Override
    void addAppsWithStateLocked(Set<Pair<String, Integer>> apps) {
        apps.addAll(appTargets.keySet());
    }

    @Override
    boolean letsThroughLocked(int rules) {
        // The OEM deny chain would also block what the app's allow rules let through.
        return (rules & FirewallMaps.SCOPE_ALLOWS) != 0;
    }

    @Override
    void fillAppRuleLocked(Pair<String, Integer> app, AppRule rule) {
        rule.ruleCount = appTargets.getOrDefault(app, Set.of()).size();
    }

    @Override
    void dumpLocked(PrintWriter pw) {
        appTargets.forEach((app, rules) -> pw.println("Rules for " + app.first
                + " user " + app.second + ": " + rules));
        userTargets.forEach((user, rules) -> pw.println("Rules for all apps of user "
                + user + " (" + rules.size() + "): " + rules.stream().limit(20).toList()));
    }

    @Override
    void writeAppsLocked(Map<Integer, Integer> wanted) {
        Map<Integer, Set<TargetRule>> targets = new HashMap<>();
        for (Map.Entry<Pair<String, Integer>, Set<TargetRule>> app :
                appTargets.entrySet()) {
            int uid = mService.knownUid(app.getKey());
            if (uid >= 0) targets.computeIfAbsent(uid, u -> new HashSet<>()).addAll(app.getValue());
        }
        Map<Integer, ScopeEntries> entries = new HashMap<>();
        targets.forEach((uid, rules) -> {
            ScopeEntries scope = entriesLocked(uid, rules);
            for (int each : FirewallService.withSdkSandbox(uid)) {
                entries.put(each, scope);
                wanted.merge(each, scope.flags(), (a, b) -> a | b);
            }
        });
        // Entries go in before the flags that enable them, and out after.
        for (int scope : new ArrayList<>(mScopeEntries.keySet())) {
            if ((scope & FirewallMaps.USER_SCOPE) == 0 && !entries.containsKey(scope)) {
                writeScopeLocked(scope, ScopeEntries.EMPTY);
            }
        }
        entries.forEach(this::writeScopeLocked);
    }

    /** Writes the rules for all of the user's apps, entries before the flags that enable them. */
    @Override
    void writeUserLocked(int userId) {
        int scope = FirewallMaps.USER_SCOPE | userId;
        ScopeEntries entries = entriesLocked(scope,
                userTargets.getOrDefault(userId, Set.of()));
        writeScopeLocked(scope, entries);
        mService.maps().setUserFlags(userId, entries.flags());
    }

    /**
     * The DNS-over-HTTPS servers browsers switch to on their own, which apps under domain rules
     * may not use, as their own DNS.
     */
    private void writeDohServersLocked() {
        List<String> lines;
        try {
            lines = Files.readAllLines(DOH_SERVERS.toPath());
        } catch (IOException e) {
            Log.w(FirewallService.TAG, "No list of DNS-over-HTTPS servers", e);
            return;
        }
        for (String line : lines) {
            String entry = line.trim();
            if (entry.isEmpty() || entry.startsWith("#")) continue;
            if (InetAddresses.isNumericAddress(entry)) {
                byte[] address = InetAddresses.parseNumericAddress(entry).getAddress();
                mService.maps().setIp(FirewallMaps.DOH_SCOPE, address, address.length * 8, false, 1);
            } else {
                mService.maps().setDomain(FirewallMaps.DOH_SCOPE, entry, FirewallMaps.DOMAIN_BLOCK);
            }
        }
    }

    /**
     * A scope's rules as map entries: the limits each range is named under per action, port and
     * domain bits per limit, and the networks of each limit after limit 0, every network.
     */
    private record ScopeEntries(Map<Pair<String, Boolean>, Integer> prefixes,
            Map<Long, Integer> ports, Map<String, Long> domains, List<Pair<Long, Long>> limits,
            int flags) {
        static final ScopeEntries EMPTY =
                new ScopeEntries(Map.of(), Map.of(), Map.of(), List.of(), 0);
        private static final Pair<Long, Long> EVERY_NETWORK = Pair.create(0L, 0L);
        private static final long DOMAIN_ALLOWS = 0xccccccccccccccccL;

        /**
         * Limits keep their numbers from the previous entries while rules use them, so answers
         * learned for allowed domains stay valid.
         */
        static ScopeEntries of(Collection<TargetRule> rules, ScopeEntries previous) {
            Map<TargetRule, Pair<Long, Long>> limitOf = new HashMap<>();
            Set<Pair<Long, Long>> wanted = new HashSet<>();
            for (TargetRule rule : rules) {
                Pair<Long, Long> limit = limitOf(rule);
                if (limit == null) continue;
                limitOf.put(rule, limit);
                if (!limit.equals(EVERY_NETWORK)) wanted.add(limit);
            }
            List<Pair<Long, Long>> limits = numberLimits(wanted, previous.limits());
            Map<Pair<Long, Long>, Integer> numbers = new HashMap<>();
            for (int i = 0; i < limits.size(); i++) {
                if (!limits.get(i).equals(EVERY_NETWORK)) numbers.put(limits.get(i), i + 1);
            }
            Map<Pair<String, Boolean>, Integer> prefixes = new HashMap<>();
            Map<Long, Integer> ports = new HashMap<>();
            Map<Integer, List<int[]>> portRanges = new HashMap<>();
            Map<String, Long> domains = new HashMap<>();
            int flags = 0;
            for (Map.Entry<TargetRule, Pair<Long, Long>> entry : limitOf.entrySet()) {
                TargetRule rule = entry.getKey();
                Integer number = entry.getValue().equals(EVERY_NETWORK) ? Integer.valueOf(0)
                        : numbers.get(entry.getValue());
                if (number == null) continue;
                flags |= rule.scopeFlags();
                switch (rule.kind()) {
                    case TargetRule.ADDRESS -> prefixes.merge(
                            Pair.create(rule.value(), rule.allow()), 1 << number, (a, b) -> a | b);
                    case TargetRule.PORT -> {
                        int[] range = TargetRule.portRange(rule.value());
                        portRanges.computeIfAbsent(rule.protocol(), p -> new ArrayList<>()).add(
                                new int[] {range[0], range[1], (rule.allow()
                                        ? FirewallMaps.PORT_ALLOW : FirewallMaps.PORT_BLOCK)
                                                << (2 * number)});
                    }
                    default -> domains.merge(rule.value(),
                            (long) rule.domainBits() << (4 * number), (a, b) -> a | b);
                }
            }
            for (Map.Entry<Integer, List<int[]>> protocol : portRanges.entrySet()) {
                Maps.putPortPrefixes(ports, protocol.getKey(), protocol.getValue());
            }
            if (!limits.isEmpty()) {
                flags |= FirewallMaps.SCOPE_LIMITS;
                inheritWiderRanges(prefixes);
            }
            return new ScopeEntries(prefixes, ports, domains, limits, flags);
        }

        /**
         * A rule's limit as the network bits it needs and those it excludes; null when no
         * network can match it.
         */
        private static Pair<Long, Long> limitOf(TargetRule rule) {
            if (rule.networks().isEmpty()) return EVERY_NETWORK;
            long bits = 0;
            for (String network : rule.networks()) {
                Integer kind = TargetRule.NETWORK_KINDS.get(network);
                if (kind != null) bits |= kind;
            }
            if (rule.exceptNetworks()) return Pair.create(0L, bits);
            return bits == 0 ? null : Pair.create(bits, 0L);
        }

        /**
         * Numbers the limits from 1, keeping previous numbers; unused numbers in between hold
         * EVERY_NETWORK, and limits past the last number are left out.
         */
        private static List<Pair<Long, Long>> numberLimits(Set<Pair<Long, Long>> wanted,
                List<Pair<Long, Long>> previous) {
            List<Pair<Long, Long>> left = new ArrayList<>(wanted);
            left.sort(Comparator.comparing((Pair<Long, Long> limit) -> limit.first)
                    .thenComparing(limit -> limit.second));
            List<Pair<Long, Long>> numbered =
                    new ArrayList<>(Collections.nCopies(FirewallMaps.LIMITS - 1, null));
            for (int i = 0; i < previous.size(); i++) {
                if (left.remove(previous.get(i))) numbered.set(i, previous.get(i));
            }
            for (int i = 0; i < numbered.size() && !left.isEmpty(); i++) {
                if (numbered.get(i) == null) numbered.set(i, left.remove(0));
            }
            int size = numbered.size();
            while (size > 0 && numbered.get(size - 1) == null) size--;
            List<Pair<Long, Long>> limits = new ArrayList<>(numbered.subList(0, size));
            limits.replaceAll(limit -> limit == null ? EVERY_NETWORK : limit);
            return List.copyOf(limits);
        }

        /** Gives each range the limits of the ranges around it, which lookups pass over. */
        private static void inheritWiderRanges(Map<Pair<String, Boolean>, Integer> prefixes) {
            Map<Pair<Boolean, Boolean>, TreeMap<Integer, Map<IpPrefix, Integer>>> tries =
                    new HashMap<>();
            for (Map.Entry<Pair<String, Boolean>, Integer> entry : prefixes.entrySet()) {
                IpPrefix prefix = new IpPrefix(entry.getKey().first);
                tries.computeIfAbsent(Pair.create(entry.getKey().second,
                                prefix.getAddress() instanceof Inet4Address), t -> new TreeMap<>())
                        .computeIfAbsent(prefix.getPrefixLength(), l -> new HashMap<>())
                        .put(prefix, entry.getValue());
            }
            tries.forEach((trie, lengths) -> lengths.forEach((length, ranges) -> {
                for (Map.Entry<IpPrefix, Integer> range : ranges.entrySet()) {
                    int limits = range.getValue();
                    for (Map.Entry<Integer, Map<IpPrefix, Integer>> wider :
                            lengths.headMap(length).entrySet()) {
                        Integer outer = wider.getValue().get(
                                new IpPrefix(range.getKey().getAddress(), wider.getKey()));
                        if (outer != null) limits |= outer;
                    }
                    prefixes.put(Pair.create(range.getKey().toString(), trie.first), limits);
                }
            }));
        }

        /** The allow bits per domain; addresses learned for them go when these change. */
        Map<String, Long> allowedDomains() {
            Map<String, Long> allowed = new HashMap<>();
            domains.forEach((name, value) -> {
                if ((value & DOMAIN_ALLOWS) != 0) allowed.put(name, value & DOMAIN_ALLOWS);
            });
            return allowed;
        }
    }

    private static <T> Set<T> union(Set<T> a, Set<T> b) {
        Set<T> all = new HashSet<>(a);
        all.addAll(b);
        return all;
    }

    /** Writes what changed in the scope's entries to the maps. */
    private void writeScopeLocked(int scope, ScopeEntries next) {
        ScopeEntries prev = mScopeEntries.getOrDefault(scope, ScopeEntries.EMPTY);
        if (prev.equals(next)) return;
        for (Pair<String, Boolean> prefix :
                union(prev.prefixes().keySet(), next.prefixes().keySet())) {
            int limits = next.prefixes().getOrDefault(prefix, 0);
            if (limits != prev.prefixes().getOrDefault(prefix, 0)) {
                IpPrefix ip = new IpPrefix(prefix.first);
                mService.maps().setIp(scope, ip.getRawAddress(), ip.getPrefixLength(), prefix.second, limits);
            }
        }
        for (long key : union(prev.ports().keySet(), next.ports().keySet())) {
            int bits = next.ports().getOrDefault(key, 0);
            if (bits != prev.ports().getOrDefault(key, 0)) {
                mService.maps().setPort(scope, (int) (key & 0xff), (int) (key >> 16),
                        (int) ((key >> 8) & 0xff), bits);
            }
        }
        for (String name : union(prev.domains().keySet(), next.domains().keySet())) {
            long bits = next.domains().getOrDefault(name, 0L);
            if (bits != prev.domains().getOrDefault(name, 0L)) mService.maps().setDomain(scope, name, bits);
        }
        if (!prev.limits().equals(next.limits())) {
            long[] only = new long[next.limits().size()];
            long[] except = new long[next.limits().size()];
            for (int i = 0; i < only.length; i++) {
                only[i] = next.limits().get(i).first;
                except[i] = next.limits().get(i).second;
            }
            mService.maps().setLimits(scope, only, except);
        }
        if (!prev.allowedDomains().equals(next.allowedDomains())) mService.maps().forgetLearned(scope);
        if (next.equals(ScopeEntries.EMPTY)) {
            mScopeEntries.remove(scope);
        } else {
            mScopeEntries.put(scope, next);
        }
    }

    private ScopeEntries entriesLocked(int scope, Collection<TargetRule> rules) {
        return ScopeEntries.of(rules, mScopeEntries.getOrDefault(scope, ScopeEntries.EMPTY));
    }

    FirewallRule[] getRulesInternal(int userId, String packageName) {
        synchronized (mService) {
            Set<TargetRule> rules = packageName == null ? userTargets.get(userId)
                    : appTargets.get(Pair.create(packageName, userId));
            if (rules == null) return new FirewallRule[0];
            return rules.stream().map(rule -> rule.toParcel(packageName, userId))
                    .toArray(FirewallRule[]::new);
        }
    }

    /** Adds the rules; returns the positions of those rejected, like a malformed address. */
    int[] addRulesInternal(FirewallRule[] rules) {
        List<Integer> rejected = new ArrayList<>();
        synchronized (mService) {
            Set<Integer> users = new HashSet<>();
            boolean apps = false;
            for (int i = 0; i < rules.length; i++) {
                FirewallRule rule = rules[i];
                try {
                    TargetRule target = TargetRule.fromParcel(rule);
                    List<Pair<String, Integer>> scope = rule.packageName == null ? null
                            : mService.sharingUidLocked(rule.packageName, rule.userId);
                    if (!fitsLocked(target, rule.userId, scope)) {
                        rejected.add(i);
                        continue;
                    }
                    if (rule.packageName == null) {
                        userTargets.computeIfAbsent(rule.userId, u -> new TreeSet<>())
                                .add(target);
                        users.add(rule.userId);
                    } else {
                        for (Pair<String, Integer> app : scope) {
                            appTargets.computeIfAbsent(app, a -> new TreeSet<>())
                                    .add(target);
                        }
                        apps = true;
                    }
                } catch (IllegalArgumentException e) {
                    rejected.add(i);
                }
            }
            if (mService.mapsReady()) {
                if (apps) mService.syncAppsLocked();
                for (int user : users) mService.syncUserLocked(user);
            }
        }
        mService.saveAsync();
        return rejected.stream().mapToInt(Integer::intValue).toArray();
    }

    /**
     * Whether the firewall can tell the networks the rule names apart: each scope has its limits
     * for at most LIMITS - 1 network lists.
     */
    private boolean fitsLocked(TargetRule rule, int userId, List<Pair<String, Integer>> apps) {
        if (rule.networks().isEmpty()) return true;
        Set<Pair<List<String>, Boolean>> limits = new HashSet<>();
        limits.add(Pair.create(rule.networks(), rule.exceptNetworks()));
        List<Set<TargetRule>> scope = new ArrayList<>();
        if (apps == null) {
            scope.add(userTargets.getOrDefault(userId, Set.of()));
        } else {
            for (Pair<String, Integer> app : apps) {
                scope.add(appTargets.getOrDefault(app, Set.of()));
            }
        }
        for (Set<TargetRule> rules : scope) {
            for (TargetRule other : rules) {
                if (!other.networks().isEmpty()) {
                    limits.add(Pair.create(other.networks(), other.exceptNetworks()));
                }
            }
        }
        if (limits.size() >= FirewallMaps.LIMITS) return false;
        return true;
    }

    void removeRulesInternal(FirewallRule[] rules) {
        synchronized (mService) {
            Set<Integer> users = new HashSet<>();
            boolean apps = false;
            for (FirewallRule rule : rules) {
                TargetRule target;
                try {
                    target = TargetRule.fromParcel(rule);
                } catch (IllegalArgumentException e) {
                    continue;
                }
                if (rule.packageName == null) {
                    removeTarget(userTargets, rule.userId, target);
                    users.add(rule.userId);
                    continue;
                }
                List<Pair<String, Integer>> shared;
                try {
                    shared = mService.sharingUidLocked(rule.packageName, rule.userId);
                } catch (IllegalArgumentException e) {
                    shared = List.of(Pair.create(rule.packageName, rule.userId));
                }
                for (Pair<String, Integer> app : shared) {
                    removeTarget(appTargets, app, target);
                }
                apps = true;
            }
            if (mService.mapsReady()) {
                if (apps) mService.syncAppsLocked();
                for (int user : users) mService.syncUserLocked(user);
            }
        }
        mService.saveAsync();
    }

    private static <K> void removeTarget(Map<K, Set<TargetRule>> rules, K key, TargetRule rule) {
        Set<TargetRule> set = rules.get(key);
        if (set != null && set.remove(rule) && set.isEmpty()) rules.remove(key);
    }

    /** Reads [block|allow address|domain|port VALUE] and the options of a rule. */
    private static FirewallRule parseRule(FirewallShellCommand shell, boolean withTarget) {
        FirewallRule rule = new FirewallRule();
        rule.subdomains = true;
        if (withTarget) {
            String action = shell.getNextArgRequired();
            if (!action.equals("block") && !action.equals("allow")) {
                throw new IllegalArgumentException("Unknown action " + action);
            }
            rule.allow = action.equals("allow");
            String kind = shell.getNextArgRequired();
            rule.kind = switch (kind) {
                case "address" -> TargetRule.ADDRESS;
                case "domain" -> TargetRule.DOMAIN;
                case "port" -> TargetRule.PORT;
                default -> throw new IllegalArgumentException("Unknown kind " + kind);
            };
            rule.value = shell.getNextArgRequired();
        }
        rule.userId = UserHandle.SYSTEM.getIdentifier();
        List<String> networks = new ArrayList<>();
        String option;
        while ((option = shell.getNextOption()) != null) {
            switch (option) {
                case "--user" -> rule.userId = Integer.parseInt(shell.getNextArgRequired());
                case "--package" -> rule.packageName = shell.getNextArgRequired();
                case "--exact" -> rule.subdomains = false;
                case "--tcp" -> rule.protocol = IFirewall.PROTOCOL_TCP;
                case "--udp" -> rule.protocol = IFirewall.PROTOCOL_UDP;
                case "--on", "--except" -> {
                    if (!networks.isEmpty() && rule.exceptNetworks != option.equals("--except")) {
                        throw new IllegalArgumentException("Either --on or --except");
                    }
                    rule.exceptNetworks = option.equals("--except");
                    networks.add(shell.getNextArgRequired());
                }
                default -> throw new IllegalArgumentException("Unknown " + option);
            }
        }
        rule.networks = networks.toArray(new String[0]);
        return rule;
    }

    @Override
    Integer onShellCommand(String cmd, FirewallShellCommand shell) {
        switch (cmd) {
            case "add-rule" -> {
                FirewallRule[] rules = {parseRule(shell, true)};
                if (addRulesInternal(rules).length > 0) {
                    throw new IllegalArgumentException("Not a valid rule");
                }
            }
            case "remove-rule" -> removeRulesInternal(new FirewallRule[] {parseRule(shell, true)});
            case "list-rules" -> {
                FirewallRule query = parseRule(shell, false);
                for (FirewallRule rule : getRulesInternal(query.userId, query.packageName)) {
                    shell.getOutPrintWriter().println(TargetRule.fromParcel(rule));
                }
            }
            default -> {
                return null;
            }
        }
        return 0;
    }

    @Override
    void onShellHelp(PrintWriter pw) {
        pw.println("  add-rule|remove-rule block|allow address|domain|port VALUE");
        pw.println("      [--package PACKAGE] [--user USER] [--exact] [--tcp|--udp]");
        pw.println("      [--on NETWORK]... | [--except NETWORK]...");
        pw.println("      Without --package the rule is for all of the user's apps. --exact");
        pw.println("      leaves a domain's subdomains out; --tcp or --udp limits a port rule,");
        pw.println("      whose VALUE is a port or a range like 6881-6889.");
        pw.println("      --on limits the rule to networks, --except to all others. NETWORK:");
        pw.println("      wifi, mobile, vpn, other, metered or roaming.");
        pw.println("  list-rules [--package PACKAGE] [--user USER]");
    }
}
