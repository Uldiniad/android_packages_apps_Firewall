/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.util.Pair;

import org.junit.Test;

import java.util.Set;

/** New apps that start blocked until their user decides. */
public class NewAppBlockingTest extends ServiceTestBase {
    @Test
    public void newInstallsStartBlockedWhenTheirUserBlocksThem() {
        FirewallService service = start();
        NewAppBlocking blocking = service.feature(NewAppBlocking.class);
        synchronized (service) {
            assertFalse(blocking.applyNewInstallDefaultLocked(PACKAGE, UID));
        }
        blocking.setNewInstallsBlockedInternal(0, true);
        synchronized (service) {
            assertTrue(blocking.applyNewInstallDefaultLocked(PACKAGE, UID));
        }
        assertEquals(FirewallMaps.BLOCK_ALL, service.getAppRulesInternal(PACKAGE, 0));
        assertTrue(blocking.isDefaultInternal(PACKAGE, 0));
    }

    @Test
    public void aBlockedNewAppIsNotedOnceItCanUseTheNetwork() throws Exception {
        FirewallService service = start();
        NewAppBlocking blocking = service.feature(NewAppBlocking.class);
        blocking.setNewInstallsBlockedInternal(0, true);
        synchronized (service) {
            blocking.applyNewInstallDefaultLocked(PACKAGE, UID);
        }
        // As when an update adds INTERNET.
        service.onPackageUpdated(PACKAGE, UID);
        Pair<String, Integer> app = Pair.create(PACKAGE, 0);
        awaitSaved(service, saved -> saved.feature(NewAppBlocking.class).notified.contains(app));

        // Deciding ends it, so the decided app is never noted again.
        service.setAppRulesInternal(PACKAGE, 0, FirewallMaps.BLOCK_ALL);
        service.onPackageUpdated(PACKAGE, UID);
        awaitSaved(service, saved -> !saved.feature(NewAppBlocking.class).notified.contains(app)
                && !saved.feature(NewAppBlocking.class).defaults.contains(app));
    }

    @Test
    public void appsWithoutInternetFromBeforeTheFirstStartStartBlocked() {
        FirewallService service = start();
        NewAppBlocking blocking = service.feature(NewAppBlocking.class);
        assertEquals(FirewallMaps.BLOCK_ALL,
                service.getAppRulesInternal(NO_INTERNET_PACKAGE, 0));
        assertTrue(blocking.isDefaultInternal(NO_INTERNET_PACKAGE, 0));
        assertEquals(0, service.getAppRulesInternal(PACKAGE, 0));
    }

    @Test
    public void laterStartsLeaveAppsWithoutInternetAsTheyAre() {
        // Such an app came with INTERNET, which an update dropped, so it isn't new.
        unstarted().store().save();
        FirewallService service = start();
        assertEquals(0, service.getAppRulesInternal(NO_INTERNET_PACKAGE, 0));
    }

    @Test
    public void decisionsWinOverNewInstallDefaults() {
        FirewallService service = start();
        NewAppBlocking blocking = service.feature(NewAppBlocking.class);
        blocking.setNewInstallsBlockedInternal(0, true);
        // Allowing is recorded, as a restore brings it back before the app is installed.
        service.setAppRulesInternal(PACKAGE, 0, 0);
        synchronized (service) {
            assertFalse(blocking.applyNewInstallDefaultLocked(PACKAGE, UID));
        }
        assertEquals(0, service.getAppRulesInternal(PACKAGE, 0));
        assertFalse(blocking.isDefaultInternal(PACKAGE, 0));
    }

    @Test
    public void theNewInstallSwitchGoesWithBackups() {
        FirewallService service = start();
        NewAppBlocking blocking = service.feature(NewAppBlocking.class);
        BackupRestore backups = service.feature(BackupRestore.class);
        blocking.setNewInstallsBlockedInternal(0, true);
        byte[] payload = backups.getBackupPayloadInternal(0);
        blocking.setNewInstallsBlockedInternal(0, false);
        backups.applyRestoreInternal(0, payload);
        assertTrue(blocking.areNewInstallsBlockedInternal(0));
    }

    @Test
    public void marksAndTheSwitchSurviveSaveAndLoad() {
        FirewallService service = unstarted();
        Pair<String, Integer> app = Pair.create("org.example.new", 10);
        service.store().apps.put(app, FirewallMaps.BLOCK_ALL);
        service.feature(NewAppBlocking.class).defaults.add(app);
        service.feature(NewAppBlocking.class).blockNewInstalls.add(10);
        service.store().save();

        FirewallService loaded = unstarted();
        loaded.store().load();
        assertEquals(Set.of(app), loaded.feature(NewAppBlocking.class).defaults);
        assertEquals(Set.of(10), loaded.feature(NewAppBlocking.class).blockNewInstalls);
    }
}
