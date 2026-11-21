/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import android.util.Pair;

import org.junit.Test;

import java.util.List;
import java.util.Set;

import java.nio.charset.StandardCharsets;

/** Backing up and restoring a user's rules. */
public class BackupRestoreTest extends ServiceTestBase {
    @Test
    public void restoreBringsBackAppSwitchesForTheSameSignerOnly() {
        FirewallService service = start();
        BackupRestore backups = service.feature(BackupRestore.class);
        service.setAppRulesInternal(PACKAGE, 0, FirewallMaps.BLOCK_CELLULAR);
        byte[] payload = backups.getBackupPayloadInternal(0);

        service.setAppRulesInternal(PACKAGE, 0, 0);
        backups.applyRestoreInternal(0, payload);
        assertEquals(FirewallMaps.BLOCK_CELLULAR, service.getAppRulesInternal(PACKAGE, 0));

        // An app of the same name from another signer doesn't inherit the rule.
        String otherSigner = new String(payload, StandardCharsets.UTF_8)
                .replaceAll("certs=\"[^\"]*\"", "certs=\"" + "00".repeat(32) + "\"");
        backups.applyRestoreInternal(0, otherSigner.getBytes(StandardCharsets.UTF_8));
        assertEquals(0, service.getAppRulesInternal(PACKAGE, 0));
    }

    @Test
    public void anotherDocumentIsRefusedAndChangesNothing() {
        FirewallService service = start();
        BackupRestore backups = service.feature(BackupRestore.class);
        service.setAppRulesInternal(PACKAGE, 0, FirewallMaps.BLOCK_CELLULAR);
        byte[] other = ("<rules><app package=\"" + PACKAGE + "\" rules=\"0\"/></rules>")
                .getBytes(StandardCharsets.UTF_8);
        assertThrows(IllegalArgumentException.class,
                () -> backups.applyRestoreInternal(0, other));
        assertEquals(FirewallMaps.BLOCK_CELLULAR, service.getAppRulesInternal(PACKAGE, 0));
    }

    @Test
    public void pendingRulesSurviveSaveAndLoad() {
        FirewallService service = unstarted();
        FirewallBackup.App later = new FirewallBackup.App("org.example.later",
                FirewallMaps.BLOCK_WIFI, Set.of("ab12"), new FirewallBackup.Parts());
        service.feature(BackupRestore.class).pending.put(Pair.create("org.example.later", 10),
                later);
        service.store().save();

        FirewallService loaded = unstarted();
        loaded.store().load();
        FirewallBackup.App read = loaded.feature(BackupRestore.class).pending
                .get(Pair.create("org.example.later", 10));
        assertEquals(List.of("org.example.later", FirewallMaps.BLOCK_WIFI, Set.of("ab12")),
                List.of(read.packageName(), read.rules(), read.certs()));
    }

    @Test
    public void restoredRulesOfAppsNotInstalledYetWaitForThem() throws Exception {
        FirewallService service = start();
        BackupRestore backups = service.feature(BackupRestore.class);
        FirewallBackup backup = new FirewallBackup();
        backup.apps.add(new FirewallBackup.App("org.example.later", FirewallMaps.BLOCK_ALL,
                Set.of(), new FirewallBackup.Parts()));
        backups.applyRestoreInternal(0,
                backup.toBytes(service.features()));
        awaitSaved(service, saved -> saved.feature(BackupRestore.class).pending
                .containsKey(Pair.create("org.example.later", 0)));
    }
}
