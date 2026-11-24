/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import android.os.Process;
import android.util.Pair;

import org.junit.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;

/** Groups of apps that follow one set of rules. */
public class GroupsTest extends ServiceTestBase {
    private static final String ADDRESS = "203.0.113.0/24";

    private static String group(String id) {
        return IFirewall.GROUP_PREFIX + id;
    }

    /** The switches written for this app, without the bits the service works out. */
    private int switches() {
        return mMaps.uids.getOrDefault(UID, 0) & FirewallBackup.USER_RULES;
    }

    private static Set<String> packages(FirewallService service) {
        return Set.copyOf(Arrays.stream(service.getAppRulesForUserInternal(0))
                .map(rule -> rule.packageName).toList());
    }

    @Test
    public void anAppInAGroupFollowsTheGroupsRulesInsteadOfItsOwn() {
        FirewallService service = start();
        Groups groups = service.feature(Groups.class);
        TargetRules targets = service.feature(TargetRules.class);
        service.setAppRulesInternal(PACKAGE, 0, FirewallMaps.BLOCK_CELLULAR);
        targets.addRulesInternal(rules(rule(PACKAGE, false, TargetRule.ADDRESS, "198.51.100.7")));
        String id = groups.addGroupInternal(0, " Work ");
        groups.setAppGroupInternal(PACKAGE, 0, id);
        // A new group allows everything, and the app's own rules are gone.
        assertEquals(0, switches());
        assertEquals(Set.of(), mMaps.ips);
        AppRule own = ownRule(service);
        assertEquals(List.of(0, 0, id), List.of(own.rules, own.ruleCount, own.group));
        assertEquals("Work", groups.getGroupsInternal(0)[0].name);

        service.setAppRulesInternal(group(id), 0, FirewallMaps.BLOCK_ALL);
        targets.addRulesInternal(rules(rule(group(id), false, TargetRule.ADDRESS, ADDRESS)));
        assertEquals(FirewallMaps.BLOCK_ALL, switches());
        assertTrue(mMaps.ips.contains(UID + ":block:" + ADDRESS));
        assertTrue(ownRule(service).blockedNow);
        // While the app follows its group, its own rules can't be set.
        assertThrows(IllegalArgumentException.class,
                () -> service.setAppRulesInternal(PACKAGE, 0, 0));
        assertEquals(1, targets.addRulesInternal(
                rules(rule(PACKAGE, true, TargetRule.ADDRESS, ADDRESS))).length);
    }

    @Test
    public void leavingOrRemovingAGroupLeavesItsAppsACopyOfItsRules() {
        FirewallService service = start();
        Groups groups = service.feature(Groups.class);
        Schedules schedules = service.feature(Schedules.class);
        String id = groups.addGroupInternal(0, "Games");
        groups.setAppGroupInternal(PACKAGE, 0, id);
        service.setAppRulesInternal(group(id), 0, FirewallMaps.BLOCK_WIFI);
        schedules.setScheduleInternal(group(id), 0, 0x1f, 22 * 60, 7 * 60);
        service.feature(TargetRules.class).addRulesInternal(
                rules(rule(group(id), false, TargetRule.ADDRESS, ADDRESS)));

        groups.setAppGroupInternal(PACKAGE, 0, null);
        AppRule own = ownRule(service);
        assertNull(own.group);
        assertEquals(List.of(FirewallMaps.BLOCK_WIFI, 1, 0x1f),
                List.of(own.rules, own.ruleCount, own.scheduleDays));
        assertEquals(FirewallMaps.BLOCK_WIFI, switches());
        assertTrue(mMaps.ips.contains(UID + ":block:" + ADDRESS));

        groups.setAppGroupInternal(PACKAGE, 0, id);
        groups.removeGroupInternal(0, id);
        own = ownRule(service);
        assertEquals(List.of(FirewallMaps.BLOCK_WIFI, 1, 0x1f),
                List.of(own.rules, own.ruleCount, own.scheduleDays));
        // The group's own rules go with it.
        assertEquals(0, groups.getGroupsInternal(0).length);
        assertFalse(packages(service).contains(group(id)));
        assertEquals(Set.of(UID + ":block:" + ADDRESS,
                Process.toSdkSandboxUid(UID) + ":block:" + ADDRESS), mMaps.ips);
    }

    @Test
    public void groupsAndTheirAppsGoWithBackups() {
        FirewallService service = start();
        Groups groups = service.feature(Groups.class);
        BackupRestore backups = service.feature(BackupRestore.class);
        String id = groups.addGroupInternal(0, "Work");
        groups.setAppGroupInternal(PACKAGE, 0, id);
        service.setAppRulesInternal(group(id), 0, FirewallMaps.BLOCK_ALL);
        byte[] payload = backups.getBackupPayloadInternal(0);

        groups.removeGroupInternal(0, id);
        backups.applyRestoreInternal(0, payload);
        assertEquals(id, ownRule(service).group);
        assertEquals(0, ownRule(service).rules);
        assertEquals(FirewallMaps.BLOCK_ALL, service.getAppRulesInternal(group(id), 0));
        assertEquals(FirewallMaps.BLOCK_ALL, switches());
    }

    @Test
    public void startKeepsGroupsButNotAppsThatAreGone() {
        FirewallService seed = unstarted();
        String id = UUID.randomUUID().toString();
        Groups saved = seed.feature(Groups.class);
        saved.groups.put(0, new TreeMap<>(Map.of(id, "Work")));
        saved.members.put(Pair.create(PACKAGE, 0), id);
        saved.members.put(Pair.create("org.example.uninstalled", 0), id);
        seed.store().apps.put(Pair.create(group(id), 0), FirewallMaps.BLOCK_ALL);
        seed.store().save();

        FirewallService service = start();
        Groups loaded = service.feature(Groups.class);
        assertEquals(Map.of(0, Map.of(id, "Work")), loaded.groups);
        assertEquals(Map.of(Pair.create(PACKAGE, 0), id), loaded.members);
        assertEquals(FirewallMaps.BLOCK_ALL, switches());
    }
}
