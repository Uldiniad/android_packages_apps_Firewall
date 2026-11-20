/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import android.os.Process;
import android.util.Pair;

import org.junit.Test;

import static android.net.ConnectivityManager.FIREWALL_CHAIN_OEM_DENY_1;
import static android.net.ConnectivityManager.FIREWALL_RULE_DEFAULT;
import static android.net.ConnectivityManager.FIREWALL_RULE_DENY;
import static org.mockito.Mockito.verify;

import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/** The core: app switches, the OEM deny chain, loopback, and listeners. */
public class FirewallServiceTest extends ServiceTestBase {
    @Test
    public void appRulesReachTheMapForTheAppAndItsSdkSandbox() {
        FirewallService service = start();
        service.setAppRulesInternal(PACKAGE, 0, FirewallMaps.BLOCK_CELLULAR);
        int rules = mMaps.uids.get(UID);
        assertEquals(FirewallMaps.BLOCK_CELLULAR, rules & FirewallMaps.BLOCK_CELLULAR);
        assertEquals(rules, (int) mMaps.uids.get(Process.toSdkSandboxUid(UID)));
    }

    @Test
    public void blockAllUsesTheOemDenyChain() {
        FirewallService service = start();
        service.setAppRulesInternal(PACKAGE, 0, FirewallMaps.BLOCK_ALL);
        verify(mConnectivity).setUidFirewallRule(FIREWALL_CHAIN_OEM_DENY_1, UID,
                FIREWALL_RULE_DENY);
        service.setAppRulesInternal(PACKAGE, 0, 0);
        verify(mConnectivity).setUidFirewallRule(FIREWALL_CHAIN_OEM_DENY_1, UID,
                FIREWALL_RULE_DEFAULT);
    }

    @Test
    public void rulesExistOnlyForInstalledApps() {
        FirewallService seed = unstarted();
        FirewallStore store = seed.store();
        store.apps.put(Pair.create("org.example.uninstalled", 0), FirewallMaps.BLOCK_ALL);
        store.save();

        FirewallService service = start();
        assertEquals(0, service.getAppRulesInternal("org.example.uninstalled", 0));
        assertThrows(IllegalArgumentException.class, () -> service.setAppRulesInternal(
                "org.example.uninstalled", 0, FirewallMaps.BLOCK_ALL));
    }

    @Test
    public void appsSharingAUidShareTheirRules() {
        FirewallService service = start();
        service.setAppRulesInternal("com.android.settings", 0, FirewallMaps.BLOCK_VPN);
        assertEquals(FirewallMaps.BLOCK_VPN, service.getAppRulesInternal("android", 0));
    }

    @Test
    public void listenersHearChanges() throws Exception {
        FirewallService service = start();
        Semaphore changes = new Semaphore(0);
        service.registerListenerInternal(new IFirewallListener.Stub() {
            @Override
            public void onChanged() {
                changes.release();
            }
        });
        service.setAppRulesInternal(PACKAGE, 0, FirewallMaps.BLOCK_WIFI);
        assertTrue(changes.tryAcquire(5, TimeUnit.SECONDS));
    }

    @Test
    public void appsWithNoNetworkLeftStayOffLoopbackWhereConnectivityCantTellWhomTheyReach() {
        FirewallService service = start();
        service.setAppRulesInternal(PACKAGE, 0, FirewallMaps.BLOCK_ALL);
        assertEquals(FirewallMaps.NO_LOOPBACK, noLoopback());
        service.setAppRulesInternal(PACKAGE, 0, 0);
        assertEquals(0, noLoopback());
    }

    @Test
    public void theServiceSaysWhetherTheFirewallIsRunning() {
        assertTrue(start().isRunningInternal());
        mMaps.ready = false;
        assertFalse(start().isRunningInternal());
    }
}
