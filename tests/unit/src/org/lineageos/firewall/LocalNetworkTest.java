/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.Map;


import static android.net.NetworkCapabilities.TRANSPORT_WIFI;
import static org.lineageos.firewall.TestNetworks.VPN;
import static org.lineageos.firewall.TestNetworks.WIFI;
import static org.lineageos.firewall.TestNetworks.caps;
import static org.lineageos.firewall.TestNetworks.link;
import static org.lineageos.firewall.TestNetworks.network;
import static org.lineageos.firewall.TestNetworks.vpn;

import android.net.LinkProperties;
import android.net.ProxyInfo;

import java.net.InetAddress;

/** Keeping apps without the local network permission off the LAN. */
public class LocalNetworkTest extends ServiceTestBase {
    @Test
    public void appsWithoutLocalNetworkPermissionAreKeptOffTheLanThroughVpns() {
        // This app targets the current SDK without requesting ACCESS_LOCAL_NETWORK.
        start();
        assertEquals(FirewallMaps.NO_LAN, (int) mMaps.uids.get(UID));
    }

    @Test
    public void lanSubnetsFollowAospsLocalNetworkPrefixes() throws Exception {
        NetworkTracker tracker = start().networks();
        tracker.onCapabilitiesChanged(network(WIFI), caps(TRANSPORT_WIFI).build());
        LinkProperties lp = link("lo", "192.168.1.5/24", "100.70.0.5/10", "203.0.113.5/24",
                "fd00:1::5/64", "2001:db8:5::5/64");
        lp.addDnsServer(InetAddress.parseNumericAddress("192.168.1.1"));
        lp.addDnsServer(InetAddress.parseNumericAddress("9.9.9.9"));
        tracker.onLinkPropertiesChanged(network(WIFI), lp);
        assertEquals(Map.of("192.168.1.0/24", FirewallMaps.LAN_LOCAL,
                "100.64.0.0/10", FirewallMaps.LAN_LOCAL,
                "fd00:1::/64", FirewallMaps.LAN_LOCAL,
                "2001:db8:5::/64", FirewallMaps.LAN_LOCAL,
                "192.168.1.1/32", FirewallMaps.LAN_DNS), mMaps.lan);

        // AOSP's local network protection doesn't apply while a proxy is set.
        lp.setHttpProxy(ProxyInfo.buildDirectProxy("proxy.test", 8080));
        tracker.onLinkPropertiesChanged(network(WIFI), lp);
        assertTrue(mMaps.lan.isEmpty());
    }

    @Test
    public void vpnSubnetsAreLeftToAosp() {
        NetworkTracker tracker = start().networks();
        tracker.onCapabilitiesChanged(network(VPN), vpn(false));
        tracker.onLinkPropertiesChanged(network(VPN), link("lo", "10.8.0.2/24"));
        assertTrue(mMaps.lan.isEmpty());
    }
}
