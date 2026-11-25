/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static android.net.ConnectivityManager.FIREWALL_CHAIN_OEM_DENY_1;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import android.os.Process;

import org.junit.Test;

import java.util.List;
import java.util.Set;

/**
 * Devices on the hotspot: their own rules, on dnsmasq's uid, and the program on the tethered
 * interfaces while the firewall is on.
 */
public class HotspotTest extends ServiceTestBase {
    @Test
    public void theProgramFollowsTheTetheredInterfacesAndTheMainSwitch() {
        FirewallService service = start();
        Hotspot hotspot = service.feature(Hotspot.class);
        hotspot.onTetheredInterfacesChanged(List.of("wlan1", "rndis0"));
        assertEquals(Set.of("wlan1", "rndis0"), mMaps.hotspots);
        hotspot.onTetheredInterfacesChanged(List.of("rndis0"));
        assertEquals(Set.of("rndis0"), mMaps.hotspots);

        MainSwitch mainSwitch = service.feature(MainSwitch.class);
        mainSwitch.setEnabledInternal(false);
        assertEquals(Set.of(), mMaps.hotspots);
        hotspot.onTetheredInterfacesChanged(List.of("rndis0", "wlan1"));
        assertEquals(Set.of(), mMaps.hotspots);
        mainSwitch.setEnabledInternal(true);
        assertEquals(Set.of("rndis0", "wlan1"), mMaps.hotspots);
    }

    @Test
    public void theDevicesRulesGoToDnsmasqsUidAndOutlastARestart() throws Exception {
        FirewallService service = start();
        service.setAppRulesInternal(IFirewall.HOTSPOT_PACKAGE, 0, FirewallMaps.BLOCK_WIFI);
        assertEquals(FirewallMaps.BLOCK_WIFI, (int) mMaps.uids.get(Process.DNS_TETHER_UID));
        awaitSaved(service, saved -> saved.getAppRulesInternal(IFirewall.HOTSPOT_PACKAGE, 0)
                == FirewallMaps.BLOCK_WIFI);
        mMaps.clearRules();
        start();
        assertEquals(FirewallMaps.BLOCK_WIFI, (int) mMaps.uids.get(Process.DNS_TETHER_UID));
    }

    @Test
    public void devicesBlockedFromAllKeepDnsmasqOffTheOemDenyChain() {
        start().setAppRulesInternal(IFirewall.HOTSPOT_PACKAGE, 0, FirewallMaps.BLOCK_ALL);
        assertEquals(FirewallMaps.BLOCK_ALL,
                mMaps.uids.get(Process.DNS_TETHER_UID) & FirewallMaps.BLOCK_ALL);
        verify(mConnectivity, never()).setUidFirewallRule(eq(FIREWALL_CHAIN_OEM_DENY_1),
                eq(Process.DNS_TETHER_UID), anyInt());
    }

    @Test
    public void rulesLimitedToNetworksReadTetheringsUpstream() {
        Hotspot hotspot = start().feature(Hotspot.class);
        hotspot.onUpstreamChanged(TestNetworks.network(105));
        assertEquals(105, mMaps.hotspotUpstream);
        hotspot.onUpstreamChanged(null);
        assertEquals(0, mMaps.hotspotUpstream);
    }
}
