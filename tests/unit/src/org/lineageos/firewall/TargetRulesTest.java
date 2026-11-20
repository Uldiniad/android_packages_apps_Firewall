/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.os.Process;
import android.util.Pair;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static android.net.ConnectivityManager.FIREWALL_CHAIN_OEM_DENY_1;
import static android.net.ConnectivityManager.FIREWALL_RULE_DEFAULT;
import static android.net.ConnectivityManager.FIREWALL_RULE_DENY;
import static org.mockito.Mockito.verify;

import static org.lineageos.firewall.TestNetworks.vpn;


/** Rules for addresses, ports and domains, per app and for all apps. */
public class TargetRulesTest extends ServiceTestBase {
    @Test
    public void portRangesReachTheMapsAsPrefixesThatDontOverlap() {
        FirewallService service = start();
        TargetRules targets = service.feature(TargetRules.class);
        assertEquals(0, targets.addRulesInternal(rules(
                rule(null, false, TargetRule.PORT, "6881 - 6889"),
                rule(null, true, TargetRule.PORT, "6885"))).length);
        int both = FirewallMaps.PORT_BLOCK | FirewallMaps.PORT_ALLOW;
        assertEquals(Map.of("u0:6881/0", FirewallMaps.PORT_BLOCK,
                "u0:6882-6883/0", FirewallMaps.PORT_BLOCK, "u0:6884/0", FirewallMaps.PORT_BLOCK,
                "u0:6885/0", both, "u0:6886-6887/0", FirewallMaps.PORT_BLOCK,
                "u0:6888-6889/0", FirewallMaps.PORT_BLOCK), mMaps.ports);
        // Kept as entered, with spaces dropped.
        assertEquals(Set.of("6881-6889", "6885"), Set.copyOf(
                Arrays.stream(targets.getRulesInternal(0, null)).map(r -> r.value).toList()));
    }

    @Test
    public void knownDohServersReachTheMapsAtStart() {
        start();
        String doh = FakeMaps.scope(FirewallMaps.DOH_SCOPE);
        assertEquals(FirewallMaps.DOMAIN_BLOCK, (long) mMaps.dohDomains.get(doh + ":dns.google"));
        assertTrue(mMaps.dohIps.contains(doh + ":block:8.8.8.8/32"));
    }

    @Test
    public void rulesAndListsOfUsersThatNoLongerExistAreDropped() {
        FirewallService seed = unstarted();
        FirewallStore store = seed.store();
        store.apps.put(Pair.create(PACKAGE, 4242), FirewallMaps.BLOCK_ALL);
        store.apps.put(Pair.create(PACKAGE, 0), FirewallMaps.BLOCK_WIFI);
        seed.feature(TargetRules.class).userTargets.put(4242, new TreeSet<>(Set.of(
                TargetRule.of(false, TargetRule.ADDRESS, "198.51.100.0/24", false, 0, List.of(),
                        false),
                TargetRule.of(false, TargetRule.DOMAIN, "gone.test", true, 0, List.of(),
                        false))));
        seed.feature(TargetRules.class).userTargets.put(0, new TreeSet<>(Set.of(
                TargetRule.of(false, TargetRule.ADDRESS, "203.0.113.0/24", false, 0, List.of(),
                        false))));
        store.save();

        FirewallService service = start();
        assertEquals(0, service.getAppRulesInternal(PACKAGE, 4242));
        assertEquals(FirewallMaps.BLOCK_WIFI, service.getAppRulesInternal(PACKAGE, 0));
        assertEquals(Set.of("u0:block:203.0.113.0/24"), mMaps.ips);
        assertEquals(Map.of(), mMaps.domains);
    }

    @Test
    public void domainsAreListedAsDnsCarriesThem() {
        FirewallService service = start();
        TargetRules targets = service.feature(TargetRules.class);
        FirewallRule exact = rule(null, false, TargetRule.DOMAIN, "B\u00fccher.Example.");
        exact.subdomains = false;
        FirewallRule wildcard = rule(null, false, TargetRule.DOMAIN, "*.ads.test");
        wildcard.subdomains = false;
        assertEquals(0, targets.addRulesInternal(rules(exact, wildcard)).length);
        assertEquals(Map.of("u0:xn--bcher-kva.example", (long) FirewallMaps.DOMAIN_BLOCK,
                "u0:ads.test",
                (long) (FirewallMaps.DOMAIN_BLOCK | FirewallMaps.DOMAIN_BLOCK_SUBDOMAINS)),
                mMaps.domains);
        assertEquals(FirewallMaps.SCOPE_DOMAINS, (int) mMaps.userFlags.get(0));
    }

    @Test
    public void malformedRulesAreRejectedByPosition() {
        FirewallService service = start();
        TargetRules targets = service.feature(TargetRules.class);
        int[] rejected = targets.addRulesInternal(rules(
                rule(null, false, TargetRule.DOMAIN, "ads.test"),
                rule(null, false, TargetRule.DOMAIN, "not a domain"),
                rule(null, false, TargetRule.PORT, "65536"),
                rule("org.example.uninstalled", false, TargetRule.PORT, "443"),
                rule(null, true, TargetRule.ADDRESS, "2001:db8::/32")));
        assertEquals(List.of(1, 2, 3), Arrays.stream(rejected).boxed().toList());
        assertEquals(2, targets.getRulesInternal(0, null).length);
    }

    @Test
    public void appRulesGoInTheAppsScopeWithTheFlagsTheyNeed() {
        FirewallService service = start();
        TargetRules targets = service.feature(TargetRules.class);
        FirewallRule udp = rule(PACKAGE, false, TargetRule.PORT, "443");
        udp.protocol = IFirewall.PROTOCOL_UDP;
        targets.addRulesInternal(rules(udp,
                rule(PACKAGE, true, TargetRule.ADDRESS, "198.51.100.7"),
                rule(PACKAGE, false, TargetRule.DOMAIN, "example.test")));
        // The SDK sandbox gets the app's rules, as it gets its switches.
        int sandbox = Process.toSdkSandboxUid(UID);
        assertEquals(Set.of(UID + ":allow:198.51.100.7/32", sandbox + ":allow:198.51.100.7/32"),
                mMaps.ips);
        assertEquals(Map.of(UID + ":443/17", FirewallMaps.PORT_BLOCK,
                sandbox + ":443/17", FirewallMaps.PORT_BLOCK), mMaps.ports);
        int flags = mMaps.uids.get(UID);
        assertEquals(FirewallMaps.SCOPE_PORT_BLOCKS | FirewallMaps.SCOPE_IP_ALLOWS
                | FirewallMaps.SCOPE_DOMAINS, flags);
        assertEquals(flags, (int) mMaps.uids.get(sandbox));
        assertEquals(3, ownRule(service).ruleCount);
    }

    @Test
    public void blockedAppsWithAllowRulesStayOffTheOemDenyChain() {
        FirewallService service = start();
        TargetRules targets = service.feature(TargetRules.class);
        service.setAppRulesInternal(PACKAGE, 0, FirewallMaps.BLOCK_ALL);
        verify(mConnectivity).setUidFirewallRule(FIREWALL_CHAIN_OEM_DENY_1, UID,
                FIREWALL_RULE_DENY);
        // The chain would also drop what the allow rule lets through.
        targets.addRulesInternal(rules(rule(PACKAGE, true, TargetRule.DOMAIN, "example.test")));
        verify(mConnectivity).setUidFirewallRule(FIREWALL_CHAIN_OEM_DENY_1, UID,
                FIREWALL_RULE_DEFAULT);
    }

    @Test
    public void connectivityKeepsAppsWithNoNetworkLeftToThemselvesWhereItCan() {
        mMaps.knowsLoopbackReceivers = true;
        FirewallService service = start();
        TargetRules targets = service.feature(TargetRules.class);
        service.setAppRulesInternal(PACKAGE, 0, FirewallMaps.BLOCK_ALL);
        assertEquals(0, noLoopback());
        // Allow rules keep the app off Connectivity's chain, so the programs keep it off loopback.
        targets.addRulesInternal(rules(rule(PACKAGE, true, TargetRule.DOMAIN, "example.test")));
        assertEquals(FirewallMaps.NO_LOOPBACK, noLoopback());
    }

    @Test
    public void changingAllowedDomainsForgetsTheirLearnedAddresses() {
        FirewallService service = start();
        TargetRules targets = service.feature(TargetRules.class);
        FirewallRule allowed = rule(PACKAGE, true, TargetRule.DOMAIN, "example.test");
        targets.addRulesInternal(rules(rule(PACKAGE, false, TargetRule.PORT, "25")));
        assertEquals(Set.of(), mMaps.forgotten);
        targets.addRulesInternal(rules(allowed));
        targets.removeRulesInternal(rules(allowed));
        assertTrue(mMaps.forgotten.contains(UID));
    }

    @Test
    public void rulesLimitedToNetworksGetANumberedLimitEach() {
        FirewallService service = start();
        TargetRules targets = service.feature(TargetRules.class);
        FirewallRule onMobile = rule(null, false, TargetRule.DOMAIN, "ads.test");
        onMobile.networks = new String[] {"mobile"};
        FirewallRule range = rule(null, false, TargetRule.ADDRESS, "198.51.100.0/24");
        FirewallRule exceptOnVpn = rule(null, false, TargetRule.ADDRESS, "198.51.100.7");
        exceptOnVpn.networks = new String[] {"vpn"};
        exceptOnVpn.exceptNetworks = true;
        assertEquals(0, targets.addRulesInternal(rules(onMobile, range, exceptOnVpn)).length);
        assertEquals(List.of(List.of(0L, (long) FirewallMaps.BLOCK_VPN),
                List.of((long) FirewallMaps.BLOCK_CELLULAR, 0L)), mMaps.limits.get("u0"));
        assertEquals(Map.of("u0:ads.test",
                (long) (FirewallMaps.DOMAIN_BLOCK | FirewallMaps.DOMAIN_BLOCK_SUBDOMAINS) << 8),
                mMaps.domains);
        // Lookups find only the narrowest range, so it carries the wider range's limits too.
        assertEquals(Map.of("u0:block:198.51.100.0/24", 1, "u0:block:198.51.100.7/32", 1 | 1 << 1),
                mMaps.ipLimits);
        assertEquals(FirewallMaps.SCOPE_LIMITS,
                mMaps.userFlags.get(0) & FirewallMaps.SCOPE_LIMITS);

        // Limits keep their numbers while rules use them.
        targets.removeRulesInternal(rules(exceptOnVpn));
        assertEquals(List.of(List.of(0L, 0L), List.of((long) FirewallMaps.BLOCK_CELLULAR, 0L)),
                mMaps.limits.get("u0"));
    }

    @Test
    public void networksBeyondWhatTheFirewallTellsApartAreRejected() {
        FirewallService service = start();
        TargetRules targets = service.feature(TargetRules.class);
        SpecificNetworks specific = service.feature(SpecificNetworks.class);
        String[] kinds = {"wifi", "mobile", "vpn", "other", "metered", "roaming"};
        List<FirewallRule> limited = new ArrayList<>();
        for (int i = 1; i <= FirewallMaps.LIMITS; i++) {
            FirewallRule rule = rule(null, false, TargetRule.DOMAIN, "ads" + i + ".test");
            List<String> networks = new ArrayList<>();
            for (int kind = 0; kind < kinds.length; kind++) {
                if ((i & (1 << kind)) != 0) networks.add(kinds[kind]);
            }
            rule.networks = networks.toArray(new String[0]);
            limited.add(rule);
        }
        // Limit 0 is every network, which leaves LIMITS - 1 for rules.
        assertArrayEquals(new int[] {FirewallMaps.LIMITS - 1},
                targets.addRulesInternal(limited.toArray(new FirewallRule[0])));

        String[] ssids = new String[FirewallMaps.SLOTS + 1];
        for (int i = 0; i < ssids.length; i++) ssids[i] = "wifi:\"Network " + i + "\"";
        FirewallRule onNetworks = rule(PACKAGE, false, TargetRule.DOMAIN, "ads.test");
        onNetworks.networks = ssids;
        assertArrayEquals(new int[] {0}, targets.addRulesInternal(rules(onNetworks)));
        onNetworks.networks = Arrays.copyOf(ssids, FirewallMaps.SLOTS);
        assertArrayEquals(new int[0], targets.addRulesInternal(rules(onNetworks)));
        assertFalse(specific.setAppNetworkInternal(PACKAGE, 0, "sim:1", IFirewall.NETWORK_BLOCK));
    }

    @Test
    public void rulesGoWithBackups() {
        FirewallService service = start();
        TargetRules targets = service.feature(TargetRules.class);
        BackupRestore backups = service.feature(BackupRestore.class);
        FirewallRule range = rule(null, false, TargetRule.ADDRESS, "198.51.100.0/24");
        FirewallRule port = rule(PACKAGE, true, TargetRule.PORT, "853");
        targets.addRulesInternal(rules(range, port));
        byte[] payload = backups.getBackupPayloadInternal(0);

        targets.removeRulesInternal(rules(range, port));
        backups.applyRestoreInternal(0, payload);
        assertEquals(Set.of("u0:block:198.51.100.0/24"), mMaps.ips);
        assertEquals(Map.of(UID + ":853/0", FirewallMaps.PORT_ALLOW,
                Process.toSdkSandboxUid(UID) + ":853/0", FirewallMaps.PORT_ALLOW), mMaps.ports);
    }

    @Test
    public void rulesSurviveSaveAndLoad() {
        FirewallService service = unstarted();
        TargetRule range = TargetRule.of(false, TargetRule.ADDRESS, "198.51.100.0/24", false, 0,
                List.of("wifi:\"Caf\u00e9, upstairs\"", "mobile"), true);
        TargetRule exact = TargetRule.of(false, TargetRule.DOMAIN, "ads.test", false, 0,
                List.of(), false);
        TargetRules targets = service.feature(TargetRules.class);
        targets.userTargets.put(10, new TreeSet<>(Set.of(range)));
        targets.appTargets.put(Pair.create("org.example.app", 10), new TreeSet<>(Set.of(exact)));
        service.store().save();

        FirewallService loaded = unstarted();
        loaded.store().load();
        assertEquals(Map.of(10, Set.of(range)), loaded.feature(TargetRules.class).userTargets);
        assertEquals(Map.of(Pair.create("org.example.app", 10), Set.of(exact)),
                loaded.feature(TargetRules.class).appTargets);
    }
}
