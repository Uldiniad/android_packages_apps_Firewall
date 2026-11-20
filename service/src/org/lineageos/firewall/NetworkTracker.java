/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.VpnTransportInfo;
import android.os.Handler;
import android.system.Os;
import android.util.Range;

import java.io.PrintWriter;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Keeps the network id and interface maps in step with each network's bits: its transport, and
 * whether it is metered or roaming.
 */
final class NetworkTracker extends ConnectivityManager.NetworkCallback {
    private final Map<Integer, Integer> mTransports = new HashMap<>();
    /** FirewallMaps.BLOCK_METERED and BLOCK_ROAMING, as each network is. */
    private final Map<Integer, Integer> mStates = new HashMap<>();
    private final Map<Integer, Set<Integer>> mInterfaces = new HashMap<>();
    private final Map<Integer, Set<Range<Integer>>> mVpnUids = new HashMap<>();
    /** Networks apps may use: with internet access and not restricted. */
    private final Set<Integer> mUsable = new HashSet<>();
    private final Set<Integer> mBypassableVpns = new HashSet<>();
    private final Maps mMaps;
    private final Handler mHandler;
    private final Runnable mOnChange;

    NetworkTracker(Maps maps, Handler handler, Runnable onChange) {
        mMaps = maps;
        mHandler = handler;
        mOnChange = onChange;
    }

    void start(Context context) {
        writeVpnRanges();
        context.getSystemService(ConnectivityManager.class).registerNetworkCallback(
                new NetworkRequest.Builder().clearCapabilities().build(), this, mHandler);
    }

    static int transportOf(NetworkCapabilities nc) {
        if (nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return FirewallMaps.BLOCK_VPN;
        if (nc.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return FirewallMaps.BLOCK_WIFI;
        if (nc.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
            return FirewallMaps.BLOCK_CELLULAR;
        }
        return FirewallMaps.BLOCK_OTHER;
    }

    private static int statesOf(NetworkCapabilities nc) {
        // Metered as Data Saver takes it.
        return (nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
                        ? 0 : FirewallMaps.BLOCK_METERED)
                | (nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING)
                        ? 0 : FirewallMaps.BLOCK_ROAMING);
    }

    private long bitsOf(int netId) {
        return mTransports.get(netId) | mStates.getOrDefault(netId, 0);
    }

    private void writeNet(int netId) {
        long bits = bitsOf(netId);
        mMaps.setNet(netId, bits);
        for (int ifindex : mInterfaces.getOrDefault(netId, Set.of())) mMaps.setIface(ifindex, bits);
    }

    @Override
    public synchronized void onCapabilitiesChanged(Network network, NetworkCapabilities nc) {
        int netId = network.getNetId();
        int transport = transportOf(nc);
        Integer previous = mTransports.put(netId, transport);
        boolean changed = previous == null || previous != transport;
        int states = statesOf(nc);
        changed |= !Integer.valueOf(states).equals(mStates.put(netId, states));
        Set<Range<Integer>> uids = transport == FirewallMaps.BLOCK_VPN ? nc.getUids() : null;
        if (uids != null && !uids.equals(mVpnUids.get(netId))) {
            mVpnUids.put(netId, uids);
            writeVpnRanges();
            changed = true;
        }
        boolean usable = nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                && nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED);
        changed |= usable ? mUsable.add(netId) : mUsable.remove(netId);
        boolean bypassable = nc.getTransportInfo() instanceof VpnTransportInfo vpn
                && vpn.isBypassable();
        changed |= bypassable ? mBypassableVpns.add(netId) : mBypassableVpns.remove(netId);
        writeNet(netId);
        if (changed) mHandler.post(mOnChange);
    }

    @Override
    public synchronized void onLinkPropertiesChanged(Network network, LinkProperties lp) {
        int netId = network.getNetId();
        Set<Integer> current = new HashSet<>();
        for (String name : lp.getAllInterfaceNames()) {
            int ifindex = Os.if_nametoindex(name);
            if (ifindex > 0) current.add(ifindex);
        }
        for (int ifindex : mInterfaces.getOrDefault(netId, Set.of())) {
            if (!current.contains(ifindex)) mMaps.setIface(ifindex, 0);
        }
        Integer transport = mTransports.get(netId);
        if (transport != null) {
            long bits = bitsOf(netId);
            for (int ifindex : current) mMaps.setIface(ifindex, bits);
        }
        mInterfaces.put(netId, current);
    }

    @Override
    public synchronized void onLost(Network network) {
        int netId = network.getNetId();
        mTransports.remove(netId);
        mStates.remove(netId);
        mMaps.setNet(netId, 0);
        if (mVpnUids.remove(netId) != null) writeVpnRanges();
        for (int ifindex : mInterfaces.getOrDefault(netId, Set.of())) {
            mMaps.setIface(ifindex, 0);
        }
        mInterfaces.remove(netId);
        mUsable.remove(netId);
        mBypassableVpns.remove(netId);
        mHandler.post(mOnChange);
    }

    /** Whether an app's switches block it on a network with these bits, as the programs decide. */
    static boolean blocks(int rules, long bits) {
        return (rules & (int) bits & FirewallMaps.NETWORKS) != 0;
    }

    /** Whether the switches block every connected network {@code uid} may use, if it has one. */
    synchronized boolean blocksEveryNetwork(int uid, int rules) {
        Integer vpn = null;
        for (Map.Entry<Integer, Set<Range<Integer>>> entry : mVpnUids.entrySet()) {
            for (Range<Integer> range : entry.getValue()) {
                if (range.contains(uid)) vpn = entry.getKey();
            }
        }
        if (vpn != null && !mBypassableVpns.contains(vpn)) {
            return blocks(rules, bitsOf(vpn));
        }
        boolean any = false;
        for (int netId : mUsable) {
            int transport = mTransports.get(netId);
            if (transport == FirewallMaps.BLOCK_VPN && !Integer.valueOf(netId).equals(vpn)) {
                continue;
            }
            if (!blocks(rules, bitsOf(netId))) return false;
            any = true;
        }
        return any;
    }

    private void writeVpnRanges() {
        List<int[]> ranges = new ArrayList<>();
        for (Map.Entry<Integer, Set<Range<Integer>>> vpn : mVpnUids.entrySet()) {
            for (Range<Integer> range : vpn.getValue()) {
                ranges.add(new int[] {range.getLower(), range.getUpper(), vpn.getKey()});
            }
        }
        int count = Math.min(ranges.size(), 32);
        int[] starts = new int[count];
        int[] ends = new int[count];
        int[] netIds = new int[count];
        for (int i = 0; i < count; i++) {
            starts[i] = ranges.get(i)[0];
            ends[i] = ranges.get(i)[1];
            netIds[i] = ranges.get(i)[2];
        }
        mMaps.setVpnRanges(starts, ends, netIds);
    }

    synchronized void dump(PrintWriter pw) {
        pw.println("Networks:");
        for (int netId : mTransports.keySet()) {
            pw.println("  netId " + netId + " bits 0x" + Long.toHexString(bitsOf(netId))
                    + " ifindexes " + mInterfaces.getOrDefault(netId, Set.of()));
        }
        pw.println("VPN UIDs: " + mVpnUids);
        pw.println("Usable: " + mUsable + ", bypassable VPNs: " + mBypassableVpns);
    }
}
