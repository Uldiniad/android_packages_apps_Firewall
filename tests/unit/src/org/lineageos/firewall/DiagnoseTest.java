/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import java.util.Arrays;
import java.util.List;

/** What a refused activity entry's page names as the rules, lists and switches behind it. */
public class DiagnoseTest extends ServiceTestBase {
    private static final String ADS = "https://lists.test/ads.txt";
    private static final String RANGES = "https://lists.test/ranges.txt";

    private static ActivityEntry refused(String name, String address, int port, int reasons) {
        ActivityEntry entry = new ActivityEntry();
        entry.key = "test";
        entry.uid = UID;
        entry.kind = IFirewall.ACTIVITY_CONNECT;
        entry.protocol = IFirewall.PROTOCOL_TCP;
        entry.name = name;
        entry.address = address;
        entry.port = port;
        entry.reasons = reasons;
        return entry;
    }

    /** Each match as "reason whose kind:value list", for one comparison. */
    private static List<String> explain(FirewallService service, ActivityEntry entry) {
        return Arrays.stream(Diagnose.explain(service, 0, entry))
                .map(match -> match.reason + " " + match.packageName + " "
                        + (match.rule != null ? match.rule.kind + ":" + match.rule.value : null)
                        + " " + match.list)
                .toList();
    }

    @Test
    public void aDomainBlockNamesTheAppsRuleApartFromTheListForAllApps() throws Exception {
        FirewallService service = start();
        service.feature(TargetRules.class).addRulesInternal(rules(
                rule(PACKAGE, false, TargetRule.DOMAIN, "example.org"),
                rule(PACKAGE, false, TargetRule.DOMAIN, "example.net")));
        BlockLists lists = service.feature(BlockLists.class);
        String id = lists.addListInternal(0, null, ADS, true);
        lists.setListContentInternal(id, open(content("ads.example.org")), "Ads", null, null,
                null);

        assertEquals(List.of(IFirewall.REASON_DOMAIN + " " + PACKAGE + " 1:example.org null",
                        IFirewall.REASON_USER_DOMAIN + " null null Ads"),
                explain(service, refused("www.ads.example.org", null, 0,
                        IFirewall.REASON_DOMAIN | IFirewall.REASON_USER_DOMAIN)));
    }

    @Test
    public void addressPortAndListBlocksNameTheRulesThatCoverTheEntry() throws Exception {
        FirewallService service = start();
        FirewallRule https = rule(PACKAGE, false, TargetRule.ADDRESS, "192.0.2.7");
        https.protocol = IFirewall.PROTOCOL_TCP;
        https.port = "443";
        FirewallRule other = rule(PACKAGE, false, TargetRule.ADDRESS, "192.0.2.8");
        FirewallRule ports = rule(null, false, TargetRule.PORT, "440-450");
        ports.protocol = IFirewall.PROTOCOL_TCP;
        service.feature(TargetRules.class).addRulesInternal(rules(https, other, ports));
        BlockLists lists = service.feature(BlockLists.class);
        String id = lists.addListInternal(0, null, RANGES, true);
        lists.setListContentInternal(id, open(content("192.0.2.0/24")), "Ranges", null, null,
                null);

        assertEquals(List.of(IFirewall.REASON_USER_LIST + " null null Ranges",
                        IFirewall.REASON_ADDRESS + " " + PACKAGE + " 0:192.0.2.7/32 null",
                        IFirewall.REASON_USER_PORT + " null 2:440-450 null"),
                explain(service, refused(null, "192.0.2.7", 443, IFirewall.REASON_USER_LIST
                        | IFirewall.REASON_ADDRESS | IFirewall.REASON_USER_PORT)));
    }

    @Test
    public void aGroupMembersEntryNamesItsGroupsRules() {
        FirewallService service = start();
        Groups groups = service.feature(Groups.class);
        String id = groups.addGroupInternal(0, "Work");
        groups.setAppGroupInternal(PACKAGE, 0, id);
        String group = IFirewall.GROUP_PREFIX + id;
        service.feature(TargetRules.class).addRulesInternal(
                rules(rule(group, false, TargetRule.ADDRESS, "198.51.100.7")));

        assertEquals(List.of(IFirewall.REASON_ADDRESS + " " + group + " 0:198.51.100.7/32 null"),
                explain(service, refused(null, "198.51.100.7", 443, IFirewall.REASON_ADDRESS)));
    }

    @Test
    public void aReasonNothingCoversAnyMoreStillShowsWithItsSwitches() {
        FirewallService service = start();

        assertEquals(List.of(IFirewall.REASON_USER_ADDRESS + " null null null",
                        IFirewall.REASON_NETWORK + " " + PACKAGE + " null null"),
                explain(service, refused(null, "203.0.113.9", 443,
                        IFirewall.REASON_USER_ADDRESS | IFirewall.REASON_NETWORK)));
    }
}
