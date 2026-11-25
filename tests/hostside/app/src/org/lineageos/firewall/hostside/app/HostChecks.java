/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall.hostside.app;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.os.Bundle;
import android.os.UserHandle;
import android.os.UserManager;

import androidx.test.platform.app.InstrumentationRegistry;

import com.android.compatibility.common.util.PollingCheck;
import com.android.compatibility.common.util.SystemUtil;

import org.junit.Test;

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
     * and says the "blocked" argument doesn't exist. Asked directly, other DNS servers never
     * answer them.
     */
    @Test
    public void tetheredLookups() throws Exception {
        Bundle args = InstrumentationRegistry.getArguments();
        try (TetheredDevice device = TetheredDevice.start()) {
            assertEquals(Firewall.NXDOMAIN, device.lookUp(args.getString("blocked")).rcode());
            Firewall.DnsAnswer allowed = device.lookUp(args.getString("allowed"));
            assertEquals(0, allowed.rcode());
            assertTrue("No addresses", allowed.answers() > 0);
            assertNull(device.lookUp(args.getString("allowed"), "1.1.1.1"));
        }
    }

    /**
     * What devices tethered to the phone send out through it follows the rules for all apps: the
     * "address" argument accepts their connection at the "port" argument, the "blocked" one
     * doesn't.
     */
    @Test
    public void tetheredTraffic() throws Exception {
        try (TetheredDevice device = TetheredDevice.start()) {
            assertTrue(device.connects(address(), port()));
            assertFalse(device.connects(
                    InstrumentationRegistry.getArguments().getString("blocked"), port()));
        }
    }

    /**
     * Devices tethered to the phone with all their traffic blocked still hear back from its DNS,
     * that names don't exist, and reach nothing through it.
     */
    @Test
    public void tetheredBlockAll() throws Exception {
        try (TetheredDevice device = TetheredDevice.start()) {
            assertEquals(Firewall.NXDOMAIN, device.lookUp("one.one.one.one").rcode());
            assertFalse(device.connects(address(), port()));
        }
    }

    /**
     * A device tethered to the phone with rules of its own: its allow rule for the "address"
     * argument wins over the hotspot's block, the hotspot's block keeps it from the "blocked"
     * argument, and its own domain rule makes the "blockedName" argument not exist for it.
     */
    @Test
    public void tetheredDeviceRules() throws Exception {
        Bundle args = InstrumentationRegistry.getArguments();
        try (TetheredDevice device = TetheredDevice.start()) {
            assertTrue(device.connects(address(), port()));
            assertFalse(device.connects(args.getString("blocked"), port()));
            assertEquals(Firewall.NXDOMAIN, device.lookUp(args.getString("blockedName")).rcode());
            assertEquals(0, device.lookUp("one.one.one.one").rcode());
        }
    }

    /** Android's resolver answers this app's lookup of the "host" argument, else example.org. */
    @Test
    public void looksUp() throws Exception {
        assertTrue(Firewall.looksUp(
                InstrumentationRegistry.getArguments().getString("host", "example.org"), 15_000));
    }
}
