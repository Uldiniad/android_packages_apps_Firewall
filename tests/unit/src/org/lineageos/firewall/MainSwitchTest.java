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
import org.mockito.InOrder;

import java.time.Instant;

import static android.net.ConnectivityManager.FIREWALL_CHAIN_OEM_DENY_1;
import static android.net.ConnectivityManager.FIREWALL_RULE_DENY;
import static org.mockito.AdditionalMatchers.aryEq;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;

/** The main switch: while it's off no app is firewalled, and the rules wait to apply again. */
public class MainSwitchTest extends ServiceTestBase {
    @Test
    public void offSwitchesTheProgramsOffAndEmptiesTheMapsAndTheChain() {
        FirewallService service = start();
        service.setAppRulesInternal(PACKAGE, 0, FirewallMaps.BLOCK_ALL);
        service.feature(MainSwitch.class).setEnabledInternal(false);
        assertFalse(mMaps.attached);
        assertFalse(service.isRunningInternal());
        assertTrue(mMaps.uids.isEmpty());
        assertTrue(mMaps.dohDomains.isEmpty());
        InOrder chain = inOrder(mConnectivity);
        chain.verify(mConnectivity).setUidFirewallRule(FIREWALL_CHAIN_OEM_DENY_1, UID,
                FIREWALL_RULE_DENY);
        chain.verify(mConnectivity).replaceFirewallChain(eq(FIREWALL_CHAIN_OEM_DENY_1),
                aryEq(new int[0]));
        chain.verify(mConnectivity).setFirewallChainEnabled(FIREWALL_CHAIN_OEM_DENY_1, false);
    }

    @Test
    public void rulesChangedWhileOffApplyOnceItsBackOn() {
        FirewallService service = start();
        MainSwitch mainSwitch = service.feature(MainSwitch.class);
        mainSwitch.setEnabledInternal(false);
        service.setAppRulesInternal(PACKAGE, 0, FirewallMaps.BLOCK_ALL);
        assertTrue(mMaps.uids.isEmpty());
        mainSwitch.setEnabledInternal(true);
        assertTrue(mMaps.attached);
        assertEquals(FirewallMaps.BLOCK_ALL, blockAll());
    }

    @Test
    public void appsBlockedAsNewWhileOffAreToldOnceItsBackOn() {
        FirewallService service = start();
        NewAppBlocking blocking = service.feature(NewAppBlocking.class);
        MainSwitch mainSwitch = service.feature(MainSwitch.class);
        blocking.setNewInstallsBlockedInternal(0, true);
        mainSwitch.setEnabledInternal(false);
        synchronized (service) {
            assertTrue(blocking.applyNewInstallDefaultLocked(PACKAGE, UID));
        }
        // As when an update adds INTERNET, which tells the user while the firewall is on.
        service.onPackageUpdated(PACKAGE, UID);
        Pair<String, Integer> app = Pair.create(PACKAGE, 0);
        synchronized (service) {
            assertFalse(blocking.notified.contains(app));
        }
        mainSwitch.setEnabledInternal(true);
        synchronized (service) {
            assertTrue(blocking.notified.contains(app));
        }
    }

    @Test
    public void theFirewallStaysOffAfterARestart() throws Exception {
        FirewallService service = start();
        service.setAppRulesInternal(PACKAGE, 0, FirewallMaps.BLOCK_ALL);
        service.feature(MainSwitch.class).setEnabledInternal(false);
        awaitSaved(service, saved -> saved.feature(MainSwitch.class).off);
        // As when the system server restarts: the programs and the maps outlive it.
        mMaps.attach();
        mMaps.setUid(UID, FirewallMaps.BLOCK_ALL);
        FirewallService restarted = start();
        assertFalse(restarted.feature(MainSwitch.class).isEnabledInternal());
        assertFalse(mMaps.attached);
        assertTrue(mMaps.uids.isEmpty());
    }

    @Test
    public void offForAWhileComesBackOnAtItsTimeEvenAcrossARestart() throws Exception {
        FirewallService service = start();
        long until = mClock.millis() + 15 * 60_000;
        service.feature(MainSwitch.class).turnOffUntilInternal(until);
        assertFalse(mMaps.attached);
        awaitSaved(service, saved -> saved.feature(MainSwitch.class).offUntil == until);

        // Before its time a restart keeps it off, still due back at the same time.
        MainSwitch restarted = start().feature(MainSwitch.class);
        restarted.onTime();
        assertFalse(restarted.isEnabledInternal());
        assertEquals(until, restarted.offUntilInternal());

        mClock.now = Instant.ofEpochMilli(until);
        restarted.onTime();
        assertTrue(restarted.isEnabledInternal());
        assertEquals(0, restarted.offUntilInternal());
        assertTrue(mMaps.attached);
    }
}
