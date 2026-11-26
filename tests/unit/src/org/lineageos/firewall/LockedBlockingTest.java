/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import android.os.UserHandle;

import org.junit.Test;

/** Apps blocked while their user is locked: on their own, or as all of the user's apps are. */
public class LockedBlockingTest extends ServiceTestBase {
    private int userFlags() {
        return mMaps.userFlags.getOrDefault(0, 0);
    }

    @Test
    public void aUserCountsAsLockedOnceTheLockIsCheckedAndUntilItIsUnlocked() {
        FirewallService service = start();
        LockedBlocking locked = service.feature(LockedBlocking.class);
        service.setAppRulesInternal(PACKAGE, 0, FirewallMaps.BLOCK_LOCKED);
        assertEquals(FirewallMaps.BLOCK_LOCKED, mMaps.uids.get(UID) & FirewallMaps.BLOCK_LOCKED);
        assertEquals(0, userFlags() & FirewallMaps.USER_LOCKED);
        synchronized (service) {
            locked.onLockStateLocked(UserHandle.USER_NULL);
        }
        assertEquals(FirewallMaps.USER_LOCKED, userFlags() & FirewallMaps.USER_LOCKED);
        synchronized (service) {
            locked.onLockStateLocked(UserHandle.USER_SYSTEM);
        }
        assertEquals(0, userFlags() & FirewallMaps.USER_LOCKED);
    }

    @Test
    public void blockingAllAppsWhileLockedOutlivesARestartAndComesBackFromABackup() {
        FirewallService service = start();
        service.feature(LockedBlocking.class).setBlockedWhileLockedInternal(0, true);
        service.setAppRulesInternal(PACKAGE, 0, FirewallMaps.ALLOW_LOCKED);
        assertEquals(FirewallMaps.USER_BLOCK_LOCKED, userFlags() & FirewallMaps.USER_BLOCK_LOCKED);
        byte[] payload = service.feature(BackupRestore.class).getBackupPayloadInternal(0);
        service.store().save();

        mMaps.userFlags.clear();
        FirewallService restarted = start();
        LockedBlocking locked = restarted.feature(LockedBlocking.class);
        assertTrue(locked.isBlockedWhileLockedInternal(0));
        assertEquals(FirewallMaps.USER_BLOCK_LOCKED, userFlags() & FirewallMaps.USER_BLOCK_LOCKED);
        locked.setBlockedWhileLockedInternal(0, false);
        restarted.setAppRulesInternal(PACKAGE, 0, 0);
        assertEquals(0, userFlags() & FirewallMaps.USER_BLOCK_LOCKED);

        restarted.feature(BackupRestore.class).applyRestoreInternal(0, payload);
        assertTrue(locked.isBlockedWhileLockedInternal(0));
        assertEquals(FirewallMaps.ALLOW_LOCKED, restarted.getAppRulesInternal(PACKAGE, 0));
    }
}
