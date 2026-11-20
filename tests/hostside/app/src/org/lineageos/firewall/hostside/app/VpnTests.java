/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall.hostside.app;

import static com.android.compatibility.common.util.SystemUtil.runShellCommand;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.content.Intent;
import android.net.InetAddresses;
import android.net.VpnService;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.InetAddress;

/** The firewall's rules for an app under a VPN, using this app's own VPN. */
public class VpnTests {
    private static final InetAddress REMOTE = address("198.51.100.1");
    private final Context mContext = Firewall.context();

    private static InetAddress address(String text) {
        return InetAddresses.parseNumericAddress(text);
    }

    @Before
    public void setUp() throws Exception {
        runShellCommand("appops set " + Firewall.PACKAGE + " ACTIVATE_VPN allow");
        Firewall.setRules("none");
    }

    @After
    public void tearDown() throws Exception {
        stopVpn();
        Firewall.setRules("none");
    }

    private void stopVpn() throws Exception {
        // The system keeps a VPN service bound while it is up; closing the tun ends the VPN.
        if (TestVpnService.sTun != null) TestVpnService.sTun.close();
        mContext.stopService(new Intent(mContext, TestVpnService.class));
        Firewall.awaitVpn(false);
    }

    private void startVpn(boolean bypassable, String exclude) throws Exception {
        startVpn(bypassable, exclude, true);
    }

    private void startVpn(boolean bypassable, String exclude, boolean metered) throws Exception {
        assertNull("VPN consent missing", VpnService.prepare(mContext));
        mContext.startService(new Intent(mContext, TestVpnService.class)
                .putExtra(TestVpnService.EXTRA_BYPASSABLE, bypassable)
                .putExtra(TestVpnService.EXTRA_EXCLUDE, exclude)
                .putExtra(TestVpnService.EXTRA_METERED, metered));
        Firewall.awaitVpn(true);
        // The app sees the VPN before the firewall has written its interface; wait for that too.
        Firewall.awaitFirewallSees(Firewall.vpnNetwork());
    }

    private static void setNetwork(String choice) {
        runShellCommand("cmd firewall set-network " + Firewall.PACKAGE + " vpn:" + Firewall.PACKAGE
                + " " + choice + " --user " + Firewall.userId());
    }

    /** Whether a UDP packet to the port reached the VPN's tun. */
    private static boolean tunSaw(int port) throws Exception {
        return Firewall.tunSaw(TestVpnService.sTun.getFileDescriptor(), port);
    }

    @Test
    public void vpnRuleBlocksTheTunnelAndWifiRuleDoesNot() throws Exception {
        startVpn(false, null);
        Firewall.setRules("vpn");
        assertFalse(Firewall.udpSends(REMOTE, 9));
        Firewall.setRules("wifi");
        assertTrue(Firewall.udpSends(REMOTE, 9));
        assertTrue("Nothing reached the tunnel", tunSaw(9));
    }

    @Test
    public void routesTheVpnExcludesFollowTheWifiRule() throws Exception {
        startVpn(false, "198.51.100.0/24");
        Firewall.setRules("wifi");
        assertFalse("Excluded route left on blocked Wi-Fi", Firewall.udpSends(REMOTE, 9));
        assertTrue("Tunnel blocked", Firewall.udpSends(address("203.0.113.1"), 9));
        // Under a non-bypassable VPN a vpn rule leaves no way out, so even excluded routes
        // are blocked, as with Lineage's per-transport toggles before.
        Firewall.setRules("vpn");
        assertFalse(Firewall.udpSends(REMOTE, 9));
    }

    @Test
    public void nonBypassableVpnLeavesNoWayOut() throws Exception {
        startVpn(false, null);
        Firewall.setRules("vpn");
        assertTrue("Not reported blocked", Firewall.waitForBlocked(true, 10_000));
        Firewall.setRules("wifi");
        assertTrue("Still reported blocked", Firewall.waitForBlocked(false, 10_000));
    }

    @Test
    public void meteredSwitchFollowsWhetherTheVpnIsMetered() throws Exception {
        startVpn(false, null, true);
        Firewall.setRules("metered");
        assertFalse(Firewall.udpSends(REMOTE, 9));
        stopVpn();
        startVpn(false, null, false);
        assertTrue(Firewall.udpSends(REMOTE, 9));
    }

    @Test
    public void aChoiceForTheVpnAppWinsOverTheVpnSwitch() throws Exception {
        startVpn(false, null);
        try {
            setNetwork("block");
            assertFalse(Firewall.udpSends(REMOTE, 9));
            Firewall.setRules("vpn");
            setNetwork("allow");
            assertTrue(Firewall.udpSends(REMOTE, 9));
            assertTrue("Nothing reached the tunnel", tunSaw(9));
        } finally {
            setNetwork("default");
        }
    }

    @Test
    public void rulesLimitedToTheVpnApplyThroughIt() throws Exception {
        startVpn(false, null);
        String rule = "cmd firewall %s block address 198.51.100.1 --package " + Firewall.PACKAGE
                + " --on %s --user " + Firewall.userId();
        runShellCommand(String.format(rule, "add-rule", "vpn"));
        try {
            assertFalse(Firewall.udpSends(REMOTE, 9));
            assertTrue(Firewall.udpSends(address("203.0.113.1"), 9));
        } finally {
            runShellCommand(String.format(rule, "remove-rule", "vpn"));
        }
        runShellCommand(String.format(rule, "add-rule", "wifi"));
        try {
            assertTrue(Firewall.udpSends(REMOTE, 9));
        } finally {
            runShellCommand(String.format(rule, "remove-rule", "wifi"));
        }
    }

    @Test
    public void bypassableVpnKeepsWifiAsAWayOut() throws Exception {
        startVpn(true, null);
        Firewall.setRules("vpn");
        assertFalse("Reported blocked", Firewall.waitForBlocked(true, 3000));
    }
}
