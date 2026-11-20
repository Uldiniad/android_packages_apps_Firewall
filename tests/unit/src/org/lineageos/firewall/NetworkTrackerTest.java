/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_METERED;
import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED;
import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING;
import static android.net.NetworkCapabilities.TRANSPORT_CELLULAR;
import static android.net.NetworkCapabilities.TRANSPORT_ETHERNET;
import static android.net.NetworkCapabilities.TRANSPORT_VPN;
import static android.net.NetworkCapabilities.TRANSPORT_WIFI;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import static org.lineageos.firewall.TestNetworks.CELLULAR;
import static org.lineageos.firewall.TestNetworks.VPN;
import static org.lineageos.firewall.TestNetworks.WIFI;
import static org.lineageos.firewall.TestNetworks.caps;
import static org.lineageos.firewall.TestNetworks.link;
import static org.lineageos.firewall.TestNetworks.network;
import static org.lineageos.firewall.TestNetworks.vpn;

import android.os.Handler;
import android.os.Looper;

import org.junit.Test;

import java.util.Map;

public class NetworkTrackerTest {
    private static final int APP = 10050;

    private final FakeMaps mMaps = new FakeMaps();
    private final NetworkTracker mTracker = new NetworkTracker(mMaps,
            new Handler(Looper.getMainLooper()), () -> {});

    @Test
    public void cellularNetworkAndItsInterfaceAreMarkedCellular() {
        mTracker.onCapabilitiesChanged(network(CELLULAR), caps(TRANSPORT_CELLULAR).build());
        mTracker.onLinkPropertiesChanged(network(CELLULAR), link("lo"));
        assertEquals(Map.of(CELLULAR, (long) FirewallMaps.BLOCK_CELLULAR), mMaps.nets);
        assertEquals(Map.of(1, (long) FirewallMaps.BLOCK_CELLULAR), mMaps.ifaces);

        mTracker.onLost(network(CELLULAR));
        assertTrue(mMaps.nets.isEmpty());
        assertTrue(mMaps.ifaces.isEmpty());
    }

    @Test
    public void vpnWinsOverItsUnderlyingTransport() {
        mTracker.onCapabilitiesChanged(network(VPN),
                caps(TRANSPORT_VPN).addTransportType(TRANSPORT_WIFI).build());
        mTracker.onCapabilitiesChanged(network(WIFI),
                caps(TRANSPORT_WIFI).addTransportType(TRANSPORT_CELLULAR).build());
        mTracker.onCapabilitiesChanged(network(CELLULAR), caps(TRANSPORT_ETHERNET).build());
        assertEquals(Map.of(VPN, (long) FirewallMaps.BLOCK_VPN,
                WIFI, (long) FirewallMaps.BLOCK_WIFI, CELLULAR, (long) FirewallMaps.BLOCK_OTHER),
                mMaps.nets);
    }

    @Test
    public void vpnUidRangesAreWrittenAndCleared() {
        mTracker.onCapabilitiesChanged(network(VPN), vpn(false));
        assertArrayEquals(new int[][] {{10000, 10100, VPN}}, mMaps.vpnRanges);
        mTracker.onLost(network(VPN));
        assertEquals(0, mMaps.vpnRanges.length);
    }

    @Test
    public void blockedEverywhereOnlyWithoutAnAllowedNetwork() {
        assertFalse("No networks", mTracker.blocksEveryNetwork(APP, FirewallMaps.BLOCK_WIFI));

        mTracker.onCapabilitiesChanged(network(WIFI), caps(TRANSPORT_WIFI).build());
        assertTrue(mTracker.blocksEveryNetwork(APP, FirewallMaps.BLOCK_WIFI));
        assertFalse(mTracker.blocksEveryNetwork(APP, FirewallMaps.BLOCK_CELLULAR));

        // A restricted network is no way out for an app.
        mTracker.onCapabilitiesChanged(network(CELLULAR), caps(TRANSPORT_CELLULAR)
                .removeCapability(NET_CAPABILITY_NOT_RESTRICTED).build());
        assertTrue(mTracker.blocksEveryNetwork(APP, FirewallMaps.BLOCK_WIFI));

        mTracker.onCapabilitiesChanged(network(CELLULAR), caps(TRANSPORT_CELLULAR).build());
        assertFalse(mTracker.blocksEveryNetwork(APP, FirewallMaps.BLOCK_WIFI));
        assertTrue(mTracker.blocksEveryNetwork(APP,
                FirewallMaps.BLOCK_WIFI | FirewallMaps.BLOCK_CELLULAR));
    }

    @Test
    public void appsUnderANonBypassableVpnOnlyHaveTheVpn() {
        mTracker.onCapabilitiesChanged(network(WIFI), caps(TRANSPORT_WIFI).build());
        mTracker.onCapabilitiesChanged(network(VPN), vpn(false));
        assertTrue(mTracker.blocksEveryNetwork(APP, FirewallMaps.BLOCK_VPN));
        assertFalse(mTracker.blocksEveryNetwork(APP, FirewallMaps.BLOCK_WIFI));
        // Outside the VPN's ranges the app goes straight to Wi-Fi.
        assertFalse(mTracker.blocksEveryNetwork(20050, FirewallMaps.BLOCK_VPN));
        assertTrue(mTracker.blocksEveryNetwork(20050, FirewallMaps.BLOCK_WIFI));
    }

    @Test
    public void appsUnderABypassableVpnCanStillUseWifi() {
        mTracker.onCapabilitiesChanged(network(WIFI), caps(TRANSPORT_WIFI).build());
        mTracker.onCapabilitiesChanged(network(VPN), vpn(true));
        assertFalse(mTracker.blocksEveryNetwork(APP, FirewallMaps.BLOCK_VPN));
        assertTrue(mTracker.blocksEveryNetwork(APP,
                FirewallMaps.BLOCK_VPN | FirewallMaps.BLOCK_WIFI));
    }

    @Test
    public void meteredAndRoamingNetworksSaySo() {
        mTracker.onCapabilitiesChanged(network(CELLULAR), caps(TRANSPORT_CELLULAR)
                .removeCapability(NET_CAPABILITY_NOT_METERED)
                .removeCapability(NET_CAPABILITY_NOT_ROAMING).build());
        assertEquals(Map.of(CELLULAR, (long) (FirewallMaps.BLOCK_CELLULAR
                | FirewallMaps.BLOCK_METERED | FirewallMaps.BLOCK_ROAMING)), mMaps.nets);
        assertTrue(mTracker.blocksEveryNetwork(APP, FirewallMaps.BLOCK_ROAMING));
        mTracker.onCapabilitiesChanged(network(CELLULAR), caps(TRANSPORT_CELLULAR).build());
        assertFalse(mTracker.blocksEveryNetwork(APP, FirewallMaps.BLOCK_ROAMING));
    }
}
