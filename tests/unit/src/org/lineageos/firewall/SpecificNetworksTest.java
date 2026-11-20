/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import android.util.Pair;

import org.junit.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;


import static android.net.NetworkCapabilities.TRANSPORT_CELLULAR;
import static android.net.NetworkCapabilities.TRANSPORT_WIFI;
import static org.lineageos.firewall.TestNetworks.CELLULAR;
import static org.lineageos.firewall.TestNetworks.HOME;
import static org.lineageos.firewall.TestNetworks.VPN;
import static org.lineageos.firewall.TestNetworks.WIFI;
import static org.lineageos.firewall.TestNetworks.caps;
import static org.lineageos.firewall.TestNetworks.network;
import static org.lineageos.firewall.TestNetworks.vpn;
import static org.lineageos.firewall.TestNetworks.vpnCaps;

import android.net.TelephonyNetworkSpecifier;

/** Apps' choices for specific networks. */
public class SpecificNetworksTest extends ServiceTestBase {
    @Test
    public void choicesForSpecificNetworksGoInTheirSlots() {
        FirewallService service = start();
        SpecificNetworks networks = service.feature(SpecificNetworks.class);
        assertTrue(networks.setAppNetworkInternal(PACKAGE, 0, "wifi:\"Home\"",
                IFirewall.NETWORK_ALLOW));
        assertTrue(networks.setAppNetworkInternal(PACKAGE, 0, "sim:3", IFirewall.NETWORK_BLOCK));
        // Each network keeps the slot it got first.
        assertEquals(List.of(1 << 1, 1), mMaps.namedNetworks.get(UID));
        assertEquals(FirewallMaps.NAMED_NETWORKS,
                mMaps.uids.get(UID) & FirewallMaps.NAMED_NETWORKS);
        AppRule rule = ownRule(service);
        assertArrayEquals(new String[] {"wifi:\"Home\""}, rule.allowedNetworks);
        assertArrayEquals(new String[] {"sim:3"}, rule.blockedNetworks);

        assertTrue(networks.setAppNetworkInternal(PACKAGE, 0, "sim:3", IFirewall.NETWORK_DEFAULT));
        assertEquals(List.of(0, 1), mMaps.namedNetworks.get(UID));
    }

    @Test
    public void choicesSurviveSaveAndLoad() {
        FirewallService service = unstarted();
        Pair<String, Integer> app = Pair.create("org.example.app", 10);
        service.feature(SpecificNetworks.class).appNetworks.put(app,
                Map.of("wifi:\"Home\"", true, "sim:2", false));
        service.store().save();

        FirewallService loaded = unstarted();
        loaded.store().load();
        assertEquals(Map.of(app, Map.of("wifi:\"Home\"", true, "sim:2", false)),
                loaded.feature(SpecificNetworks.class).appNetworks);
    }

    @Test
    public void choicesGoWithBackups() {
        FirewallService service = start();
        SpecificNetworks networks = service.feature(SpecificNetworks.class);
        BackupRestore backups = service.feature(BackupRestore.class);
        networks.setAppNetworkInternal(PACKAGE, 0, "vpn:org.example.vpn", IFirewall.NETWORK_BLOCK);
        byte[] payload = backups.getBackupPayloadInternal(0);
        networks.setAppNetworkInternal(PACKAGE, 0, "vpn:org.example.vpn",
                IFirewall.NETWORK_DEFAULT);
        backups.applyRestoreInternal(0, payload);
        assertEquals(Map.of("vpn:org.example.vpn", false),
                networks.appNetworks.get(Pair.create(PACKAGE, 0)));
    }

    @Test
    public void specificNetworksCarryTheirSlots() {
        FirewallService service = start();
        SpecificNetworks networks = service.feature(SpecificNetworks.class);
        String ownVpn = "vpn:" + PACKAGE;
        assertTrue(networks.setAppNetworkInternal(PACKAGE, 0, HOME, IFirewall.NETWORK_ALLOW));
        assertTrue(networks.setAppNetworkInternal(PACKAGE, 0, ownVpn, IFirewall.NETWORK_BLOCK));
        NetworkTracker tracker = service.networks();
        tracker.onCapabilitiesChanged(network(WIFI), caps(TRANSPORT_WIFI).setSsid("\"Home\"")
                .build());
        tracker.onCapabilitiesChanged(network(CELLULAR), caps(TRANSPORT_CELLULAR)
                .setNetworkSpecifier(new TelephonyNetworkSpecifier(3)).build());
        tracker.onCapabilitiesChanged(network(VPN), vpnCaps(false)
                .setAdministratorUids(new int[] {UID}).build());
        assertEquals(Set.of(HOME, "sim:3", ownVpn), networks.connectedKeys());
        assertEquals(Map.of(WIFI, FirewallMaps.BLOCK_WIFI | 1L << 32,
                CELLULAR, (long) FirewallMaps.BLOCK_CELLULAR,
                VPN, FirewallMaps.BLOCK_VPN | 1L << 33), mMaps.nets);
    }
}
