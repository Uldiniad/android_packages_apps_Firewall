/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall.hostside.app;

import android.content.Intent;
import android.net.IpPrefix;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import java.io.IOException;
import java.net.InetAddress;

/** A VPN that routes everything into a tun the tests read; nothing is forwarded. */
public class TestVpnService extends VpnService {
    static final String EXTRA_BYPASSABLE = "bypassable";
    static final String EXTRA_EXCLUDE = "exclude";
    static final String EXTRA_METERED = "metered";
    static volatile ParcelFileDescriptor sTun;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Builder builder = new Builder().setSession("FirewallTest").setBlocking(false)
                .addAddress("10.10.0.2", 32).addRoute("0.0.0.0", 0)
                .addAddress("fd10::2", 128).addRoute("::", 0);
        if (intent.getBooleanExtra(EXTRA_BYPASSABLE, false)) builder.allowBypass();
        builder.setMetered(intent.getBooleanExtra(EXTRA_METERED, true));
        String exclude = intent.getStringExtra(EXTRA_EXCLUDE);
        if (exclude != null) {
            String[] parts = exclude.split("/");
            builder.excludeRoute(new IpPrefix(parseAddress(parts[0]), Integer.parseInt(parts[1])));
        }
        sTun = builder.establish();
        return START_NOT_STICKY;
    }

    private static InetAddress parseAddress(String address) {
        try {
            return InetAddress.getByName(address);
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public void onDestroy() {
        try {
            if (sTun != null) sTun.close();
        } catch (IOException e) {
            // Already closed.
        }
        sTun = null;
    }
}
