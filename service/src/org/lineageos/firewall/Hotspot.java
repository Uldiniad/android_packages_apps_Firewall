/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.net.Network;
import android.net.TetheringManager;
import android.os.Process;
import android.os.UserHandle;
import android.util.Log;
import android.util.Pair;

import java.util.List;

/**
 * Devices on the phone's hotspot and tethering: what they send out through the phone follows
 * their own rules, kept as an app's are under IFirewall.HOTSPOT_PACKAGE in the main user, then the
 * rules for all of that user's apps. The hotspot program is on each tethered interface while the
 * firewall is on, and reads rules limited to networks against Tethering's upstream.
 */
final class Hotspot extends Feature implements TetheringManager.TetheringEventCallback {
    private static final Pair<String, Integer> DEVICES =
            Pair.create(IFirewall.HOTSPOT_PACKAGE, UserHandle.USER_SYSTEM);

    /** The tethered interfaces, as Tethering last reported them. */
    private List<String> mTethered = List.of();

    Hotspot(FirewallService service) {
        super(service);
    }

    /** dnsmasq's uid stands for the devices, in their lookups and in the hotspot program. */
    @Override
    int[] memberUidsLocked(Pair<String, Integer> app) {
        return DEVICES.equals(app) ? new int[] {Process.DNS_TETHER_UID} : null;
    }

    /** dnsmasq keeps answering the devices whatever their rules, which the OEM deny chain stops. */
    @Override
    boolean letsThroughLocked(int uid, int rules) {
        return uid == Process.DNS_TETHER_UID;
    }

    @Override
    void onBootPhase() {
        if (!mService.mapsReady()) return;
        mService.context().getSystemService(TetheringManager.class)
                .registerTetheringEventCallback(mService.handler()::post, this);
    }

    @Override
    public void onTetheredInterfacesChanged(List<String> interfaces) {
        synchronized (mService) {
            for (String iface : mTethered) {
                if (!interfaces.contains(iface)) setOn(iface, false);
            }
            mTethered = List.copyOf(interfaces);
            applyLocked();
        }
    }

    @Override
    public void onUpstreamChanged(Network network) {
        int error = mService.maps().setHotspotUpstream(network != null ? network.getNetId() : 0);
        if (error != 0) {
            Log.e(FirewallService.TAG, "Failed to write the hotspot's upstream: " + error);
        }
    }

    @Override
    void onTurnedOffLocked() {
        applyLocked();
    }

    @Override
    void onTurnedOnLocked() {
        applyLocked();
    }

    /** Puts the program on the tethered interfaces while the firewall is on, else takes it off. */
    private void applyLocked() {
        for (String iface : mTethered) setOn(iface, !mService.offLocked());
    }

    private void setOn(String iface, boolean on) {
        int error = on ? mService.maps().attachHotspot(iface)
                : mService.maps().detachHotspot(iface);
        if (error != 0) {
            Log.e(FirewallService.TAG, "Failed to " + (on ? "attach" : "detach")
                    + " the hotspot program on " + iface + ": " + error);
        }
    }
}
