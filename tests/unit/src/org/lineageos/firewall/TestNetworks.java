/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET;
import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_METERED;
import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING;
import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN;
import static android.net.NetworkCapabilities.TRANSPORT_VPN;

import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnManager;
import android.net.VpnTransportInfo;
import android.util.Range;

import java.util.Set;

/** Networks as Connectivity reports them, for tests that feed a NetworkTracker. */
final class TestNetworks {
    static final int WIFI = 100;
    static final int CELLULAR = 101;
    static final int VPN = 102;
    static final String HOME = "wifi:\"Home\"";

    private TestNetworks() {}

    static Network network(int netId) {
        return Network.fromNetworkHandle(((long) netId << 32) | 0xcafed00dL);
    }

    static NetworkCapabilities.Builder caps(int transport) {
        return new NetworkCapabilities.Builder().addTransportType(transport)
                .addCapability(NET_CAPABILITY_INTERNET).addCapability(NET_CAPABILITY_NOT_METERED)
                .addCapability(NET_CAPABILITY_NOT_ROAMING);
    }

    static NetworkCapabilities.Builder vpnCaps(boolean bypassable) {
        return caps(TRANSPORT_VPN).removeCapability(NET_CAPABILITY_NOT_VPN)
                .setUids(Set.of(new Range<>(10000, 10100)))
                .setTransportInfo(new VpnTransportInfo(VpnManager.TYPE_VPN_SERVICE, null,
                        bypassable, false));
    }

    static NetworkCapabilities vpn(boolean bypassable) {
        return vpnCaps(bypassable).build();
    }

    static LinkProperties link(String iface, String... addresses) {
        LinkProperties lp = new LinkProperties();
        lp.setInterfaceName(iface);
        for (String address : addresses) lp.addLinkAddress(new LinkAddress(address));
        return lp;
    }
}
