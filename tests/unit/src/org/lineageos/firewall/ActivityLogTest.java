/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.lineageos.firewall.TestNetworks.WIFI;
import static org.lineageos.firewall.TestNetworks.caps;
import static org.lineageos.firewall.TestNetworks.network;

import android.net.InetAddresses;
import android.net.NetworkCapabilities;
import android.os.SystemClock;
import android.system.OsConstants;

import org.junit.Test;

import java.net.InetAddress;
import java.time.Duration;
import java.util.List;

/** Each user's activity log, from the BPF programs' reports and the resolver's. */
public class ActivityLogTest extends ServiceTestBase {
    private static final InetAddress ADDRESS = InetAddresses.parseNumericAddress("192.0.2.7");
    // The resolver's results for a lookup the firewall refused, and for a blocked app's.
    private static final int EAI_SYSTEM = 11;
    private static final int EAI_FAIL = 4;

    /** A report of packets of 100 bytes each. */
    private static Maps.Refusal report(boolean allowed, long count, int reasons) {
        long now = SystemClock.elapsedRealtimeNanos();
        return new Maps.Refusal(new Maps.RefusalKey(UID, IFirewall.ACTIVITY_OUT,
                OsConstants.IPPROTO_UDP, ADDRESS, 443, allowed), count, reasons, now - 1_000_000,
                now, 0, 0, count * 100);
    }

    private int userFlags() {
        return mMaps.userFlags.getOrDefault(0, 0);
    }

    @Test
    public void aUsersLogTurnsOnWhatTheProgramsReportAndOutlivesARestart() {
        FirewallService service = start();
        ActivityLog log = service.feature(ActivityLog.class);
        assertFalse(log.isActivityLogInternal(0));
        log.setActivityLogInternal(0, true);
        assertEquals(FirewallMaps.USER_LOG, userFlags() & FirewallMaps.USER_LOG);
        assertTrue(mMaps.lookupsWanted);
        service.store().save();

        mMaps.userFlags.clear();
        FirewallService restarted = start();
        assertTrue(restarted.feature(ActivityLog.class).isActivityLogInternal(0));
        assertEquals(FirewallMaps.USER_LOG, userFlags() & FirewallMaps.USER_LOG);
        restarted.feature(ActivityLog.class).setActivityLogInternal(0, false);
        assertEquals(0, userFlags() & FirewallMaps.USER_LOG);
        assertFalse(mMaps.lookupsWanted);
    }

    @Test
    public void trafficIsLoggedWithTheNameTheAppLookedUpForItsAddress() {
        FirewallService service = start();
        ActivityLog log = service.feature(ActivityLog.class);
        RefusalCounts counts = service.feature(RefusalCounts.class);
        // Nothing is logged while the user's log is off.
        counts.onRefusals(List.of(report(false, 1, IFirewall.REASON_ALL)));
        assertEquals(0, log.takeActivityInternal(0).length);

        log.setActivityLogInternal(0, true);
        synchronized (service) {
            log.onLookupsLocked(List.of(new Maps.Lookup(UID, 0, "example.test", List.of(ADDRESS))));
        }
        counts.onRefusals(List.of(report(true, 3, 0)));
        ActivityEntry[] entries = log.takeActivityInternal(0);
        assertEquals(1, entries.length);
        ActivityEntry entry = entries[0];
        assertEquals(List.of(UID, IFirewall.ACTIVITY_OUT, OsConstants.IPPROTO_UDP, 443, 3L, 300L),
                List.of(entry.uid, entry.kind, entry.protocol, entry.port, entry.count,
                        entry.bytes));
        assertEquals("example.test", entry.name);
        assertEquals("192.0.2.7", entry.address);
        assertTrue(entry.allowed);
        assertTrue(entry.firstMillis <= entry.lastMillis);
        // Taken entries are the firewall app's to keep.
        assertEquals(0, log.takeActivityInternal(0).length);
    }

    @Test
    public void aRefusedConnectIsLoggedOnTheNetworkItsSocketWasFor() {
        FirewallService service = start();
        service.networks().onCapabilitiesChanged(network(WIFI),
                caps(NetworkCapabilities.TRANSPORT_WIFI).build());
        ActivityLog log = service.feature(ActivityLog.class);
        log.setActivityLogInternal(0, true);
        long now = SystemClock.elapsedRealtimeNanos();
        // Refused before any packet went out, so the report has the socket's network, no interface.
        service.feature(RefusalCounts.class).onRefusals(List.of(new Maps.Refusal(
                new Maps.RefusalKey(UID, IFirewall.ACTIVITY_CONNECT, OsConstants.IPPROTO_TCP,
                        ADDRESS, 443, false), 1, IFirewall.REASON_ADDRESS, now, now, 0, WIFI, 0)));
        ActivityEntry entry = log.takeActivityInternal(0)[0];
        assertEquals(IFirewall.ACTIVITY_CONNECT, entry.kind);
        assertEquals(FirewallMaps.BLOCK_WIFI, entry.network);
    }

    @Test
    public void refusedLookupsAreLoggedWithRepeatsWithinAMinuteInOneEntry() {
        FirewallService service = start();
        ActivityLog log = service.feature(ActivityLog.class);
        log.setActivityLogInternal(0, true);
        Maps.Lookup refused = new Maps.Lookup(UID, EAI_SYSTEM, "ads.example.test", List.of());
        synchronized (service) {
            log.onLookupsLocked(List.of(refused, refused));
        }
        ActivityEntry[] entries = log.takeActivityInternal(0);
        assertEquals(1, entries.length);
        ActivityEntry first = entries[0];
        assertEquals(IFirewall.ACTIVITY_LOOKUP, first.kind);
        assertEquals("ads.example.test", first.name);
        assertNull(first.address);
        assertEquals(IFirewall.REASON_DOMAIN, first.reasons);
        assertEquals(2, first.count);

        // A repeat after the firewall app took the entry comes back as the same entry.
        synchronized (service) {
            log.onLookupsLocked(List.of(refused));
        }
        ActivityEntry again = log.takeActivityInternal(0)[0];
        assertEquals(first.key, again.key);
        assertEquals(3, again.count);

        // A blocked app's lookups count as blocked everywhere, and a minute later start afresh.
        mClock.now = mClock.now.plus(Duration.ofMinutes(2));
        synchronized (service) {
            log.onLookupsLocked(List.of(refused,
                    new Maps.Lookup(UID, EAI_FAIL, "example.test", List.of())));
        }
        entries = log.takeActivityInternal(0);
        assertEquals(2, entries.length);
        assertFalse(first.key.equals(entries[0].key));
        assertEquals(IFirewall.REASON_ALL, entries[1].reasons);
    }
}
