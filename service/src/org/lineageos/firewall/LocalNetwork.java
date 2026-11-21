/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.Manifest;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.ApplicationInfoFlags;
import android.net.IpPrefix;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.os.Process;
import android.os.UserHandle;
import android.os.UserManager;

import java.io.PrintWriter;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Keeps apps without Android's local network permission (Nearby devices) off the local network,
 * also through VPNs, which AOSP's own protection doesn't cover: the lan maps hold each non-VPN
 * network's local subnets, and the uid map marks the apps without the permission.
 */
final class LocalNetwork extends Feature implements NetworkTracker.LinkListener {
    private static final List<IpPrefix> IPV4_LOCAL = List.of(new IpPrefix("169.254.0.0/16"),
            new IpPrefix("100.64.0.0/10"), new IpPrefix("10.0.0.0/8"),
            new IpPrefix("172.16.0.0/12"), new IpPrefix("192.168.0.0/16"));

    /** Apps without ACCESS_LOCAL_NETWORK, kept off the LAN through VPNs too. */
    private final Set<Integer> mNoLanUids = new HashSet<>();
    /** Local subnets of each non-VPN network, as AOSP's local network protection sees them. */
    private final Map<Integer, Map<IpPrefix, Integer>> mLan = new HashMap<>();
    private final Map<IpPrefix, Integer> mLanWritten = new HashMap<>();

    LocalNetwork(FirewallService service) {
        super(service);
        service.networks().addLinkListener(this);
    }

    @Override
    void onMapsClearedLocked() {
        scanLocalNetworkLocked();
        // The subnets come with the networks, under the tracker's lock.
        synchronized (mService.networks()) {
            mLanWritten.clear();
            writeLan();
        }
    }

    @Override
    void onResyncLocked() {
        scanLocalNetworkLocked();
    }

    @Override
    void onBootPhase() {
        if (!mService.mapsReady()) return;
        mService.context().getPackageManager().addOnPermissionsChangeListener(
                uid -> mService.handler().post(() -> onPermissionsChanged(uid)));
    }

    @Override
    void writeAppsLocked(Map<Integer, Integer> wanted) {
        for (int uid : mNoLanUids) {
            for (int each : FirewallService.withSdkSandbox(uid)) {
                wanted.merge(each, FirewallMaps.NO_LAN, (a, b) -> a | b);
            }
        }
    }

    private boolean lacksLocalNetwork(int uid) {
        return UserHandle.getAppId(uid) >= Process.FIRST_APPLICATION_UID
                && mService.context().checkPermission(Manifest.permission.ACCESS_LOCAL_NETWORK,
                        -1, uid) != PackageManager.PERMISSION_GRANTED;
    }

    private void scanLocalNetworkLocked() {
        mNoLanUids.clear();
        try {
            mService.context().getPackageManager().getPermissionInfo(
                    Manifest.permission.ACCESS_LOCAL_NETWORK, 0);
        } catch (PackageManager.NameNotFoundException e) {
            return;
        }
        for (UserHandle user : mService.context().getSystemService(UserManager.class)
                .getUserHandles(true)) {
            PackageManager pm = mService.context().createContextAsUser(user, 0)
                    .getPackageManager();
            for (ApplicationInfo app : pm.getInstalledApplications(
                    ApplicationInfoFlags.of(FirewallService.PACKAGE_FLAGS))) {
                if (lacksLocalNetwork(app.uid)) mNoLanUids.add(app.uid);
            }
        }
    }

    void onPermissionsChanged(int uid) {
        synchronized (mService) {
            boolean lacks = lacksLocalNetwork(uid);
            if (lacks ? mNoLanUids.add(uid) : mNoLanUids.remove(uid)) mService.syncAppsLocked();
        }
    }

    @Override
    public void onLinkProperties(int netId, int transport, LinkProperties lp) {
        if (transport == FirewallMaps.BLOCK_VPN) return;
        mLan.put(netId, lanOf(lp));
        writeLan();
    }

    @Override
    public void onLost(int netId) {
        if (mLan.remove(netId) != null) writeLan();
    }

    @Override
    public void dump(PrintWriter pw) {
        pw.println("LAN under VPNs: " + mLanWritten);
    }

    /** The on-link subnets AOSP treats as local, and the DNS servers inside them. */
    private static Map<IpPrefix, Integer> lanOf(LinkProperties lp) {
        Map<IpPrefix, Integer> lan = new HashMap<>();
        if (lp.getHttpProxy() != null) return lan;
        for (LinkAddress address : lp.getLinkAddresses()) {
            IpPrefix prefix = new IpPrefix(address.getAddress(), address.getPrefixLength());
            boolean local = prefix.getAddress() instanceof Inet6Address
                    ? prefix.getPrefixLength() != 0
                    : IPV4_LOCAL.stream().anyMatch(p -> p.contains(prefix.getAddress())
                            && prefix.getPrefixLength() >= p.getPrefixLength());
            if (local) lan.put(prefix, FirewallMaps.LAN_LOCAL);
        }
        List<IpPrefix> subnets = new ArrayList<>(lan.keySet());
        for (InetAddress dns : lp.getDnsServers()) {
            if (subnets.stream().anyMatch(p -> p.contains(dns))) {
                lan.put(new IpPrefix(dns, dns instanceof Inet4Address ? 32 : 128),
                        FirewallMaps.LAN_DNS);
            }
        }
        return lan;
    }

    private void writeLan() {
        Map<IpPrefix, Integer> wanted = new HashMap<>();
        for (Map<IpPrefix, Integer> lan : mLan.values()) wanted.putAll(lan);
        for (IpPrefix prefix : mLanWritten.keySet()) {
            if (!wanted.containsKey(prefix)) {
                mService.maps().setLan(prefix.getRawAddress(), prefix.getPrefixLength(), 0);
            }
        }
        for (Map.Entry<IpPrefix, Integer> entry : wanted.entrySet()) {
            if (!entry.getValue().equals(mLanWritten.get(entry.getKey()))) {
                mService.maps().setLan(entry.getKey().getRawAddress(),
                        entry.getKey().getPrefixLength(), entry.getValue());
            }
        }
        mLanWritten.clear();
        mLanWritten.putAll(wanted);
    }
}
