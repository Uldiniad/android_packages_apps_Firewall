/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import java.util.List;
import java.util.Set;

/** Devices on the hotspot: the program is on the tethered interfaces while the firewall is on. */
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
    public void rulesLimitedToNetworksReadTetheringsUpstream() {
        Hotspot hotspot = start().feature(Hotspot.class);
        hotspot.onUpstreamChanged(TestNetworks.network(105));
        assertEquals(105, mMaps.hotspotUpstream);
        hotspot.onUpstreamChanged(null);
        assertEquals(0, mMaps.hotspotUpstream);
    }
}
