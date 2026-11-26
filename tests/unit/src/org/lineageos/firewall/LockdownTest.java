/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** A user's lockdown, which blocks all of its apps but those let through. */
public class LockdownTest extends ServiceTestBase {
    private int userFlags() {
        return mMaps.userFlags.getOrDefault(0, 0);
    }

    @Test
    public void lockdownIsAUserFlagThatOutlivesARestartAndARestoreButIsntBackedUp() {
        FirewallService service = start();
        service.feature(Lockdown.class).setLockdownInternal(0, true);
        assertEquals(FirewallMaps.USER_LOCKDOWN, userFlags() & FirewallMaps.USER_LOCKDOWN);
        service.setAppRulesInternal(PACKAGE, 0, FirewallMaps.ALLOW_LOCKDOWN);
        assertEquals(FirewallMaps.ALLOW_LOCKDOWN,
                mMaps.uids.get(UID) & FirewallMaps.ALLOW_LOCKDOWN);
        byte[] payload = service.feature(BackupRestore.class).getBackupPayloadInternal(0);
        service.store().save();

        mMaps.userFlags.clear();
        FirewallService restarted = start();
        Lockdown lockdown = restarted.feature(Lockdown.class);
        assertTrue(lockdown.isLockdownInternal(0));
        assertEquals(FirewallMaps.USER_LOCKDOWN, userFlags() & FirewallMaps.USER_LOCKDOWN);

        // A mode rather than a rule: a restore leaves it as it is, and brings back the exception.
        BackupRestore backups = restarted.feature(BackupRestore.class);
        restarted.setAppRulesInternal(PACKAGE, 0, 0);
        backups.applyRestoreInternal(0, payload);
        assertTrue(lockdown.isLockdownInternal(0));
        assertEquals(FirewallMaps.USER_LOCKDOWN, userFlags() & FirewallMaps.USER_LOCKDOWN);
        assertEquals(FirewallMaps.ALLOW_LOCKDOWN, restarted.getAppRulesInternal(PACKAGE, 0));
        lockdown.setLockdownInternal(0, false);
        backups.applyRestoreInternal(0, payload);
        assertFalse(lockdown.isLockdownInternal(0));
        assertEquals(0, userFlags() & FirewallMaps.USER_LOCKDOWN);
    }
}
