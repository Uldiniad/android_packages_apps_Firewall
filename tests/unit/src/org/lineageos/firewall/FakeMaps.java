/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static org.junit.Assert.assertTrue;

import android.net.IpPrefix;
import android.os.SystemClock;

import java.io.FileDescriptor;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Keeps map writes in memory; a value of 0 deletes, as in the native maps. */
final class FakeMaps implements Maps {
    final Map<Integer, Integer> uids = new HashMap<>();
    /** The slots of the specific networks each uid is blocked and allowed on. */
    final Map<Integer, List<Integer>> namedNetworks = new HashMap<>();
    final Map<Integer, Long> ifaces = new HashMap<>();
    final Map<Integer, Long> nets = new HashMap<>();
    final Map<String, Integer> lan = new HashMap<>();
    final Map<Integer, Integer> userFlags = new HashMap<>();
    /** Rule entries, keyed "scope:block|allow:prefix", "scope:domain" and "scope:port/protocol". */
    final Set<String> ips = new HashSet<>();
    /** The limits of each entry in ips. */
    final Map<String, Integer> ipLimits = new HashMap<>();
    final Map<String, Long> domains = new HashMap<>();
    /** The known DNS-over-HTTPS servers' entries, apart from the rules'. */
    final Set<String> dohIps = new HashSet<>();
    final Map<String, Long> dohDomains = new HashMap<>();
    final Map<String, Integer> ports = new HashMap<>();
    /** Each scope's limits from limit 1 on, as only and except network bits. */
    final Map<String, List<List<Long>>> limits = new HashMap<>();
    /** Scopes whose learned addresses were dropped. */
    final Set<Integer> forgotten = new HashSet<>();
    /** The slots of each scope's lists, of the lists holding each range, and slots' files. */
    final Map<String, Long> scopeLists = new HashMap<>();
    final Map<String, Long> listRanges = new HashMap<>();
    final Map<Integer, Integer> listFiles = new HashMap<>();
    int[][] vpnRanges = new int[0][];

    /** A uid, or "u" and the user id for the rules for all of a user's apps. */
    static String scope(int scope) {
        return (scope & FirewallMaps.USER_SCOPE) != 0
                ? "u" + (scope & ~FirewallMaps.USER_SCOPE) : Integer.toString(scope);
    }

    private static <K, V extends Number> int put(Map<K, V> map, K key, V value) {
        if (value.longValue() == 0) map.remove(key); else map.put(key, value);
        return 0;
    }

    /** Whether the maps are there, as the BPF loader pinned them. */
    boolean ready = true;
    /** Whether the kernel lets Connectivity know whose socket an app reaches over loopback. */
    boolean knowsLoopbackReceivers;
    /** Whether the programs are on, which they stay across a restart of the service. */
    boolean attached;

    @Override public boolean init() { return ready; }
    @Override public boolean attach() {
        attached = true;
        return true;
    }
    @Override public boolean detach() {
        attached = false;
        return true;
    }
    @Override public boolean knowsLoopbackReceivers() { return knowsLoopbackReceivers; }
    @Override public void clearRules() {
        uids.clear();
        namedNetworks.clear();
        ifaces.clear();
        nets.clear();
        lan.clear();
        userFlags.clear();
        ips.clear();
        ipLimits.clear();
        domains.clear();
        dohIps.clear();
        dohDomains.clear();
        ports.clear();
        limits.clear();
        scopeLists.clear();
        listRanges.clear();
        listFiles.clear();
    }
    @Override public synchronized int setUid(int uid, int rules) {
        notifyAll();
        return put(uids, uid, rules);
    }

    /** Waits for the service's thread to set {@code rules} for {@code uid}. */
    synchronized void awaitUid(int uid, int rules) throws InterruptedException {
        long deadline = SystemClock.uptimeMillis() + 5000;
        while ((uids.getOrDefault(uid, 0) & rules) != rules) {
            long left = deadline - SystemClock.uptimeMillis();
            assertTrue("uid " + uid + " never got rules " + rules, left > 0);
            wait(left);
        }
    }
    @Override public int setNamedNetworks(int uid, int block, int allow) {
        if (block == 0 && allow == 0) namedNetworks.remove(uid);
        else namedNetworks.put(uid, List.of(block, allow));
        return 0;
    }
    @Override public int setUserFlags(int user, int flags) {
        return put(userFlags, user, flags);
    }
    @Override public int setIface(int ifindex, long net) { return put(ifaces, ifindex, net); }
    @Override public int setNet(int netId, long net) { return put(nets, netId, net); }
    @Override public void setVpnRanges(int[] starts, int[] ends, int[] netIds) {
        vpnRanges = new int[starts.length][];
        for (int i = 0; i < starts.length; i++) {
            vpnRanges[i] = new int[] {starts[i], ends[i], netIds[i]};
        }
    }
    @Override public int setIp(int scope, byte[] address, int prefixLength, boolean allow,
            int limits) {
        try {
            String key = scope(scope) + ":" + (allow ? "allow" : "block") + ":"
                    + new IpPrefix(InetAddress.getByAddress(address), prefixLength);
            if (scope == FirewallMaps.DOH_SCOPE) {
                if (limits != 0) dohIps.add(key); else dohIps.remove(key);
            } else {
                if (limits != 0) ips.add(key); else ips.remove(key);
                put(ipLimits, key, limits);
            }
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(e);
        }
        return 0;
    }
    @Override public int setLan(byte[] address, int prefixLength, int kind) {
        try {
            String key = new IpPrefix(InetAddress.getByAddress(address), prefixLength).toString();
            if (kind == 0) lan.remove(key); else lan.put(key, kind);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(e);
        }
        return 0;
    }
    @Override public int setDomain(int scope, String domain, long bits) {
        return put(scope == FirewallMaps.DOH_SCOPE ? dohDomains : domains,
                scope(scope) + ":" + domain, bits);
    }
    @Override public int setLimits(int scope, long[] only, long[] except) {
        List<List<Long>> written = new ArrayList<>();
        for (int i = 0; i < only.length; i++) written.add(List.of(only[i], except[i]));
        if (written.isEmpty()) limits.remove(scope(scope)); else limits.put(scope(scope), written);
        return 0;
    }
    @Override public int setPort(int scope, int protocol, int port, int prefixLength, int bits) {
        int last = port + (1 << (16 - prefixLength)) - 1;
        String ports = last == port ? Integer.toString(port) : port + "-" + last;
        return put(this.ports, scope(scope) + ":" + ports + "/" + protocol, bits);
    }
    @Override public void forgetLearned(int scope) {
        forgotten.add(scope);
    }
    @Override public int setScopeLists(int scope, long slots) {
        return put(scopeLists, scope(scope), slots);
    }
    @Override public int setListRange(byte[] address, int prefixLength, long slots) {
        try {
            IpPrefix range = new IpPrefix(InetAddress.getByAddress(address), prefixLength);
            return put(listRanges, range.toString(), slots);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(e);
        }
    }
    @Override public int setListFile(int slot, int generation) {
        return put(listFiles, slot, generation);
    }
    @Override public long[] counters() { return new long[0]; }
    @Override public FileDescriptor refusalsFd() { return null; }
    @Override public List<Refusal> consumeRefusals() { return List.of(); }
    @Override public List<Refusal> refusalStats() { return List.of(); }
}
