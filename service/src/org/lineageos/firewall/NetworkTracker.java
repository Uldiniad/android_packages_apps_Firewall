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
 * Keeps the network id and interface maps in step with each network's bits: its transport,
 * whether it is metered or roaming, and the bits features add, like a specific network's slot.
 */
final class NetworkTracker extends ConnectivityManager.NetworkCallback {
    /** A feature's bits for a network, from its capabilities; called with the tracker's lock. */
    interface BitsSource {
        long bitsOf(NetworkCapabilities nc, int transport);
    }

    /** A feature that follows networks' link properties; called with the tracker's lock. */
    interface LinkListener {
        void onLinkProperties(int netId, int transport, LinkProperties lp);
        void onLost(int netId);
        void dump(PrintWriter pw);
    }

    private final Map<Integer, Integer> mTransports = new HashMap<>();
    /** FirewallMaps.BLOCK_METERED and BLOCK_ROAMING, as each network is. */
    private final Map<Integer, Integer> mStates = new HashMap<>();
    /** Each network's capabilities, from which sources take their bits. */
    private final Map<Integer, NetworkCapabilities> mCapabilities = new HashMap<>();
    /** Each network's bits from the sources, as last written. */
    private final Map<Integer, Long> mSourceBits = new HashMap<>();
    private final List<BitsSource> mSources = new ArrayList<>();
    private final List<LinkListener> mLinkListeners = new ArrayList<>();
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

    synchronized void addBitsSource(BitsSource source) {
        mSources.add(source);
    }

    synchronized void addLinkListener(LinkListener listener) {
        mLinkListeners.add(listener);
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

    private long sourceBitsOf(int netId) {
        long bits = 0;
        for (BitsSource source : mSources) {
            bits |= source.bitsOf(mCapabilities.get(netId), mTransports.get(netId));
        }
        return bits;
    }

    private long bitsOf(int netId) {
        return mTransports.get(netId) | mStates.getOrDefault(netId, 0)
                | mSourceBits.getOrDefault(netId, 0L);
    }

    private void writeNet(int netId) {
        long bits = bitsOf(netId);
        mMaps.setNet(netId, bits);
        for (int ifindex : mInterfaces.getOrDefault(netId, Set.of())) mMaps.setIface(ifindex, bits);
    }

    /** Takes the sources' bits again, as what they give changed, and writes those that did. */
    synchronized void refreshSourceBits() {
        for (int netId : mTransports.keySet()) {
            long bits = sourceBitsOf(netId);
            if (!Long.valueOf(bits).equals(mSourceBits.put(netId, bits))) writeNet(netId);
        }
    }

    /** The capabilities of the networks the device is on. */
    synchronized List<NetworkCapabilities> connectedCapabilities() {
        return new ArrayList<>(mCapabilities.values());
    }

    @Override
    public synchronized void onCapabilitiesChanged(Network network, NetworkCapabilities nc) {
        int netId = network.getNetId();
        int transport = transportOf(nc);
        Integer previous = mTransports.put(netId, transport);
        boolean changed = previous == null || previous != transport;
        int states = statesOf(nc);
        changed |= !Integer.valueOf(states).equals(mStates.put(netId, states));
        mCapabilities.put(netId, nc);
        long sourceBits = sourceBitsOf(netId);
        changed |= !Long.valueOf(sourceBits).equals(mSourceBits.put(netId, sourceBits));
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
        if (transport != null) {
            for (LinkListener listener : mLinkListeners) {
                listener.onLinkProperties(netId, transport, lp);
            }
        }
    }

    @Override
    public synchronized void onLost(Network network) {
        int netId = network.getNetId();
        mTransports.remove(netId);
        mStates.remove(netId);
        mCapabilities.remove(netId);
        mSourceBits.remove(netId);
        mMaps.setNet(netId, 0);
        if (mVpnUids.remove(netId) != null) writeVpnRanges();
        for (int ifindex : mInterfaces.getOrDefault(netId, Set.of())) {
            mMaps.setIface(ifindex, 0);
        }
        mInterfaces.remove(netId);
        mUsable.remove(netId);
        mBypassableVpns.remove(netId);
        for (LinkListener listener : mLinkListeners) listener.onLost(netId);
        mHandler.post(mOnChange);
    }

    /**
     * Whether an app's switches block it on a network with these bits, as the BPF programs decide:
     * its choice for a specific network wins over the switches for the network's kind.
     */
    static boolean blocks(int rules, int blockSlots, int allowSlots, long bits) {
        int slots = (int) (bits >>> 32);
        if ((allowSlots & slots) != 0) return false;
        return (rules & (int) bits & FirewallMaps.NETWORKS) != 0 || (blockSlots & slots) != 0;
    }

    /** Whether the switches block every connected network {@code uid} may use, if it has one. */
    synchronized boolean blocksEveryNetwork(int uid, int rules) {
        return blocksEveryNetwork(uid, rules, 0, 0);
    }

    /** The same, with the slots of the specific networks the app is blocked and allowed on. */
    synchronized boolean blocksEveryNetwork(int uid, int rules, int blockSlots, int allowSlots) {
        Integer vpn = null;
        for (Map.Entry<Integer, Set<Range<Integer>>> entry : mVpnUids.entrySet()) {
            for (Range<Integer> range : entry.getValue()) {
                if (range.contains(uid)) vpn = entry.getKey();
            }
        }
        if (vpn != null && !mBypassableVpns.contains(vpn)) {
            return blocks(rules, blockSlots, allowSlots, bitsOf(vpn));
        }
        boolean any = false;
        for (int netId : mUsable) {
            int transport = mTransports.get(netId);
            if (transport == FirewallMaps.BLOCK_VPN && !Integer.valueOf(netId).equals(vpn)) {
                continue;
            }
            if (!blocks(rules, blockSlots, allowSlots, bitsOf(netId))) return false;
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
        for (LinkListener listener : mLinkListeners) listener.dump(pw);
    }
}
