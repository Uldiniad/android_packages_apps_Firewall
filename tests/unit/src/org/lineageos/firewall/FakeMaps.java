/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static org.junit.Assert.assertTrue;

import android.os.SystemClock;

import java.util.HashMap;
import java.util.Map;

/** Keeps map writes in memory; a value of 0 deletes, as in the native maps. */
final class FakeMaps implements Maps {
    final Map<Integer, Integer> uids = new HashMap<>();
    final Map<Integer, Long> ifaces = new HashMap<>();
    final Map<Integer, Long> nets = new HashMap<>();
    int[][] vpnRanges = new int[0][];

    private static <K, V extends Number> int put(Map<K, V> map, K key, V value) {
        if (value.longValue() == 0) map.remove(key); else map.put(key, value);
        return 0;
    }

    /** Whether the maps are there, as the BPF loader pinned them. */
    boolean ready = true;
    /** Whether the kernel lets Connectivity know whose socket an app reaches over loopback. */
    boolean knowsLoopbackReceivers;

    @Override public boolean init() { return ready; }
    @Override public boolean attach() { return true; }
    @Override public boolean knowsLoopbackReceivers() { return knowsLoopbackReceivers; }
    @Override public void clearRules() {
        uids.clear();
        ifaces.clear();
        nets.clear();
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
    @Override public int setIface(int ifindex, long net) { return put(ifaces, ifindex, net); }
    @Override public int setNet(int netId, long net) { return put(nets, netId, net); }
    @Override public void setVpnRanges(int[] starts, int[] ends, int[] netIds) {
        vpnRanges = new int[starts.length][];
        for (int i = 0; i < starts.length; i++) {
            vpnRanges[i] = new int[] {starts[i], ends[i], netIds[i]};
        }
    }
    @Override public long[] counters() { return new long[0]; }
}
