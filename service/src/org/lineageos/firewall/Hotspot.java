/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.net.Network;
import android.net.TetheringManager;
import android.util.Log;

import java.util.List;

/**
 * Devices on the phone's hotspot and tethering: what they send out through the phone follows the
 * rules for all of its first user's apps. The hotspot program is on each tethered interface while
 * the firewall is on, and reads rules limited to networks against Tethering's upstream.
 */
final class Hotspot extends Feature implements TetheringManager.TetheringEventCallback {
    /** The tethered interfaces, as Tethering last reported them. */
    private List<String> mTethered = List.of();

    Hotspot(FirewallService service) {
        super(service);
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
