/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall.hostside.app;

import static android.Manifest.permission.CONNECTIVITY_USE_RESTRICTED_NETWORKS;
import static android.Manifest.permission.MANAGE_TEST_NETWORKS;
import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_METERED;
import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED;
import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED;
import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VCN_MANAGED;
import static android.net.NetworkCapabilities.TRANSPORT_TEST;

import static com.android.compatibility.common.util.SystemUtil.runWithShellPermissionIdentity;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.InetAddresses;
import android.net.IpPrefix;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkAgentConfig;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.RouteInfo;
import android.net.TestNetworkInterface;
import android.net.TestNetworkManager;
import android.net.TestNetworkSpecifier;
import android.os.HandlerThread;
import android.os.Process;

import com.android.compatibility.common.util.PollingCheck;
import com.android.testutils.TestableNetworkAgent;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.InetAddress;
import java.util.List;
import java.util.Set;

/**
 * The firewall's switches on networks this app brings up as Android's test networks, as
 * Connectivity's own tests do. Test networks of other kinds admit only their carrier's app, and
 * Android marks all but mobile networks not roaming, so mobile and roaming stay with the BPF tests.
 */
public class TestNetworkTests {
    private static final InetAddress REMOTE = InetAddresses.parseNumericAddress("198.51.100.1");
    private static final LinkAddress ADDRESS = new LinkAddress("192.0.2.2/24");
    private static final InetAddress GATEWAY = InetAddresses.parseNumericAddress("192.0.2.1");

    private final Context mContext = Firewall.context();
    private final ConnectivityManager mCm = mContext.getSystemService(ConnectivityManager.class);
    private final ConnectivityManager.NetworkCallback mRequest =
            new ConnectivityManager.NetworkCallback();
    private final HandlerThread mThread = new HandlerThread("TestNetworkTests");
    private TestNetworkInterface mTun;
    private TestableNetworkAgent mAgent;

    @Before
    public void setUp() {
        mThread.start();
        Firewall.setRules("none");
    }

    @After
    public void tearDown() throws Exception {
        if (mAgent != null) {
            mCm.unregisterNetworkCallback(mRequest);
            mAgent.unregister();
        }
        if (mTun != null) mTun.getFileDescriptor().close();
        mThread.quitSafely();
        Firewall.setRules("none");
    }

    /** Brings up a restricted network on a tun that lets this app in, metered unless it isn't. */
    private Network connect(boolean metered) throws Exception {
        // As shell, which may make test networks and keep restricted ones up.
        Network network = runWithShellPermissionIdentity(() -> {
            mTun = mContext.getSystemService(TestNetworkManager.class)
                    .createTunInterface(List.of(ADDRESS));
            String iface = mTun.getInterfaceName();
            TestNetworkSpecifier specifier = new TestNetworkSpecifier(iface);
            NetworkCapabilities.Builder nc = new NetworkCapabilities.Builder()
                    .addTransportType(TRANSPORT_TEST)
                    .addCapability(NET_CAPABILITY_NOT_SUSPENDED)
                    .addCapability(NET_CAPABILITY_NOT_VCN_MANAGED)
                    .removeCapability(NET_CAPABILITY_NOT_RESTRICTED)
                    .setNetworkSpecifier(specifier)
                    .setAllowedUids(Set.of(Process.myUid()));
            if (!metered) nc.addCapability(NET_CAPABILITY_NOT_METERED);
            LinkProperties lp = new LinkProperties();
            lp.setInterfaceName(iface);
            lp.addLinkAddress(ADDRESS);
            // Through a gateway: Android takes addresses on a directly connected route as local
            // ones, which this app may not reach.
            lp.addRoute(new RouteInfo(new IpPrefix("0.0.0.0/0"), GATEWAY, iface,
                    RouteInfo.RTN_UNICAST));
            // Connectivity tears down networks no request needs.
            mCm.requestNetwork(new NetworkRequest.Builder().clearCapabilities()
                    .addTransportType(TRANSPORT_TEST).setNetworkSpecifier(specifier).build(),
                    mRequest);
            mAgent = new TestableNetworkAgent(mContext, mThread.getLooper(), nc.build(), lp,
                    new NetworkAgentConfig.Builder().build());
            mAgent.register();
            mAgent.markConnected();
            return mAgent.getNetwork();
        }, MANAGE_TEST_NETWORKS, CONNECTIVITY_USE_RESTRICTED_NETWORKS);
        Firewall.awaitFirewallSees(network);
        return network;
    }

    private boolean tunSaw() throws Exception {
        return Firewall.tunSaw(mTun.getFileDescriptor().getFileDescriptor(), 9);
    }

    @Test
    public void otherSwitchBlocksNetworksOfNoKnownKind() throws Exception {
        Network other = connect(false);
        Firewall.setRules("mobile");
        assertTrue("Blocked by the mobile switch", Firewall.udpSends(other, REMOTE, 9));
        assertTrue("Nothing reached the network", tunSaw());
        Firewall.setRules("other");
        assertFalse("Not blocked by the other switch", Firewall.udpSends(other, REMOTE, 9));
        Firewall.setRules("mobile");
        assertTrue("Still blocked once the switch is off", Firewall.udpSends(other, REMOTE, 9));
    }

    @Test
    public void meteredSwitchFollowsTheNetwork() throws Exception {
        Network network = connect(true);
        Firewall.setRules("metered");
        assertFalse(Firewall.udpSends(network, REMOTE, 9));
        // As when the network stops being metered.
        mAgent.sendNetworkCapabilities(new NetworkCapabilities.Builder(mAgent.getNc())
                .addCapability(NET_CAPABILITY_NOT_METERED).build());
        PollingCheck.waitFor(10_000, () -> Firewall.udpSends(network, REMOTE, 9),
                "Still blocked once unmetered");
        assertTrue("Nothing reached the network", tunSaw());
    }
}
