/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall.hostside.app;

import static android.Manifest.permission.MANAGE_TEST_NETWORKS;
import static android.Manifest.permission.NETWORK_SETTINGS;
import static android.Manifest.permission.TETHER_PRIVILEGED;
import static android.net.TetheringManager.CONNECTIVITY_SCOPE_GLOBAL;
import static android.net.TetheringManager.TETHERING_VIRTUAL;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.net.TestNetworkInterface;
import android.net.TestNetworkManager;
import android.net.TetheringManager;
import android.net.TetheringManager.TetheringRequest;
import android.os.Bundle;
import android.os.UserHandle;
import android.os.UserManager;

import androidx.test.platform.app.InstrumentationRegistry;

import com.android.compatibility.common.util.PollingCheck;
import com.android.compatibility.common.util.SystemUtil;

import org.junit.Test;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/** Checks the host runs after changing state it controls, like rebooting or adding a user. */
public class HostChecks {
    @Test
    public void blocked() throws Exception {
        assertTrue("Not reported blocked", Firewall.waitForBlocked(true, 15_000));
        assertFalse(Firewall.tcpConnects("1.1.1.1", 443));
    }

    /** A connection to the "address" argument, 1.1.1.1 without one, is refused. */
    @Test
    public void refused() throws Exception {
        assertFalse(Firewall.tcpConnects(address(), port()));
    }

    /** The "address" argument, as for refused. */
    private static String address() {
        return InstrumentationRegistry.getArguments().getString("address", "1.1.1.1");
    }

    /** The "port" argument, 443 without one. */
    private static int port() {
        return Integer.parseInt(InstrumentationRegistry.getArguments().getString("port", "443"));
    }

    /** Another device reaches the app's server at the "port" argument. */
    @Test
    public void reached() throws Exception {
        assertTrue(Firewall.accepts(port(), 15_000));
    }

    /** No other device reaches the app's server at the "port" argument. */
    @Test
    public void notReached() throws Exception {
        assertFalse(Firewall.accepts(port(), 8_000));
    }

    /**
     * Turns on quiet mode for the profile the "profile" argument names, as pausing work apps or
     * locking private space does.
     */
    @Test
    public void enableQuietMode() throws Exception {
        setQuietMode(true);
    }

    @Test
    public void disableQuietMode() throws Exception {
        setQuietMode(false);
    }

    private static void setQuietMode(boolean enabled) {
        int user = Integer.parseInt(InstrumentationRegistry.getArguments().getString("profile"));
        UserHandle profile = UserHandle.of(user);
        UserManager users = Firewall.context().getSystemService(UserManager.class);
        SystemUtil.runWithShellPermissionIdentity(() -> {
            users.requestQuietModeEnabled(enabled, profile);
            PollingCheck.waitFor(30_000, () -> users.isQuietModeEnabled(profile) == enabled,
                    "Quiet mode never changed");
        }, "android.permission.MODIFY_QUIET_MODE");
    }

    @Test
    public void allowed() throws Exception {
        assertTrue("No usable network", Firewall.waitForUsableNetwork(30_000));
        assertTrue(Firewall.tcpConnects(address(), port()));
    }

    /**
     * Devices tethered to the phone look names up through it: it answers the "allowed" argument
     * and says the "blocked" argument doesn't exist. A test interface stands in for the hotspot,
     * with a device behind it.
     */
    @Test
    public void tetheredLookups() throws Exception {
        Bundle args = InstrumentationRegistry.getArguments();
        TestNetworkInterface tap = SystemUtil.runWithShellPermissionIdentity(
                () -> Firewall.context().getSystemService(TestNetworkManager.class)
                        .createTapInterface(), MANAGE_TEST_NETWORKS);
        String iface = tap.getInterfaceName();
        TetheringManager tethering = Firewall.context().getSystemService(TetheringManager.class);
        TetheringRequest request = new TetheringRequest.Builder(TETHERING_VIRTUAL)
                .setConnectivityScope(CONNECTIVITY_SCOPE_GLOBAL)
                .setInterfaceName(iface)
                .build();
        CompletableFuture<Integer> started = new CompletableFuture<>();
        try {
            // Until it's connected to the tethering service, the manager queues calls for later,
            // so the shell's permissions stay until the answer comes.
            int result = SystemUtil.callWithShellPermissionIdentity(() -> {
                tethering.startTethering(request, Runnable::run,
                        new TetheringManager.StartTetheringCallback() {
                            @Override
                            public void onTetheringStarted() {
                                started.complete(0);
                            }

                            @Override
                            public void onTetheringFailed(int error) {
                                started.complete(error);
                            }
                        });
                return started.get(30, TimeUnit.SECONDS);
            }, TETHER_PRIVILEGED, NETWORK_SETTINGS);
            assertEquals("Tethering failed", 0, result);
            TetheredDevice device = new TetheredDevice(tap.getFileDescriptor().getFileDescriptor(),
                    Firewall.ipv4Of(iface, 10_000));
            assertEquals(Firewall.NXDOMAIN, device.lookUp(args.getString("blocked")).rcode());
            Firewall.DnsAnswer allowed = device.lookUp(args.getString("allowed"));
            assertEquals(0, allowed.rcode());
            assertTrue("No addresses", allowed.answers() > 0);
        } finally {
            SystemUtil.runWithShellPermissionIdentity(
                    () -> tethering.stopTethering(TETHERING_VIRTUAL), TETHER_PRIVILEGED);
            tap.getFileDescriptor().close();
        }
    }

    /** Android's resolver answers this app's lookup of the "host" argument, else example.org. */
    @Test
    public void looksUp() throws Exception {
        assertTrue(Firewall.looksUp(
                InstrumentationRegistry.getArguments().getString("host", "example.org"), 15_000));
    }
}
