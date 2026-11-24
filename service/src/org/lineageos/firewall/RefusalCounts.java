/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.os.MessageQueue;
import android.os.SystemClock;
import android.os.UserHandle;
import android.system.OsConstants;
import android.util.Log;

import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.net.Inet6Address;
import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

/**
 * The BPF programs' reports of what they refused, each app's refusals to one far end counted
 * with their reasons, of which the dump keeps the latest.
 */
final class RefusalCounts extends Feature {
    private static final int MAX_REFUSALS = 200;
    // Just past the BPF programs' minute between reports of a flow.
    private static final long REFUSAL_COLLECT_DELAY_MS = 61_000;

    /** The latest refusals by where they went, the last updated last, for dumpsys. */
    private final LinkedHashMap<Maps.RefusalKey, LoggedRefusal> mRefusals = new LinkedHashMap<>();
    private final Runnable mCollectRefusals = this::collectRefusals;
    private long mRefusalsCollectedNanos;

    RefusalCounts(FirewallService service) {
        super(service);
    }

    @Override
    void onStarted() {
        if (mService.mapsReady()) listenForRefusals();
    }

    @Override
    void dumpMaps(PrintWriter pw) {
        synchronized (mService) {
            pw.println("Recent refusals:");
            mRefusals.forEach((key, logged) -> pw.println("  " + describe(key, logged)));
        }
    }

    private void listenForRefusals() {
        FileDescriptor fd = mService.maps().refusalsFd();
        if (fd == null) return;
        mService.handler().getLooper().getQueue().addOnFileDescriptorEventListener(fd,
                MessageQueue.OnFileDescriptorEventListener.EVENT_INPUT
                        | MessageQueue.OnFileDescriptorEventListener.EVENT_ERROR,
                this::onRefusalsReady);
    }

    private int onRefusalsReady(FileDescriptor fd, int events) {
        if ((events & MessageQueue.OnFileDescriptorEventListener.EVENT_ERROR) != 0) {
            Log.e(FirewallService.TAG, "Refusals stopped");
            return 0;
        }
        onRefusals(mService.maps().consumeRefusals());
        // The refusals that come after a flow's last report are collected once reports stop.
        mService.handler().removeCallbacks(mCollectRefusals);
        mService.handler().postDelayed(mCollectRefusals, REFUSAL_COLLECT_DELAY_MS);
        return MessageQueue.OnFileDescriptorEventListener.EVENT_INPUT
                | MessageQueue.OnFileDescriptorEventListener.EVENT_ERROR;
    }

    private void collectRefusals() {
        long now = SystemClock.elapsedRealtimeNanos();
        long since = mRefusalsCollectedNanos;
        mRefusalsCollectedNanos = now;
        onRefusals(mService.maps().refusalStats().stream().filter(r -> r.lastNanos() > since).toList());
    }

    /** An app's refusals to one far end, counting those of map entries the BPF programs dropped. */
    private static final class LoggedRefusal {
        long earlier;
        long count;
        long entryFirstNanos;
        long firstNanos;
        long lastNanos;
        int reasons;
    }

    void onRefusals(List<Maps.Refusal> refusals) {
        synchronized (mService) {
            for (Maps.Refusal refusal : refusals) {
                if (refusal.key().allowed()) continue;
                LoggedRefusal logged = mRefusals.remove(refusal.key());
                if (logged == null) {
                    logged = new LoggedRefusal();
                    logged.entryFirstNanos = refusal.firstNanos();
                    logged.firstNanos = refusal.firstNanos();
                } else if (logged.entryFirstNanos != refusal.firstNanos()) {
                    // The map dropped the flow, and counts it afresh.
                    logged.earlier += logged.count;
                    logged.count = 0;
                    logged.entryFirstNanos = refusal.firstNanos();
                }
                logged.count = Math.max(logged.count, refusal.count());
                logged.lastNanos = Math.max(logged.lastNanos, refusal.lastNanos());
                logged.reasons |= refusal.reasons();
                mRefusals.put(refusal.key(), logged);
                if (mRefusals.size() > MAX_REFUSALS) {
                    mRefusals.remove(mRefusals.keySet().iterator().next());
                }
            }
            ActivityLog log = mService.feature(ActivityLog.class);
            if (log != null) log.onTrafficLocked(refusals);
        }
    }

    /**
     * As in "12:03:41–12:05:10 org.example user 0, connect tcp 192.0.2.1:443 refused 37 times:
     * address, all", the most specific reason first.
     */
    private String describe(Maps.RefusalKey key, LoggedRefusal logged) {
        String[] packages = mService.context().getPackageManager().getPackagesForUid(key.uid());
        String address = key.address().getHostAddress();
        if (key.address() instanceof Inet6Address) address = "[" + address + "]";
        String protocol = key.protocol() == OsConstants.IPPROTO_TCP ? "tcp"
                : key.protocol() == OsConstants.IPPROTO_UDP ? "udp"
                : "protocol " + key.protocol();
        List<String> reasons = new ArrayList<>();
        for (int bit : FirewallMaps.REFUSAL_REASON_ORDER) {
            if ((logged.reasons & (1 << bit)) != 0) reasons.add(FirewallMaps.REFUSAL_REASONS[bit]);
        }
        String first = timeOf(logged.firstNanos);
        String last = timeOf(logged.lastNanos);
        long count = logged.earlier + logged.count;
        return (first.equals(last) ? first : first + "–" + last) + " "
                + (packages == null ? key.uid() : String.join(", ", packages)) + " user "
                + UserHandle.getUserHandleForUid(key.uid()).getIdentifier() + ", "
                + FirewallMaps.REFUSAL_DIRECTIONS[key.direction()] + " " + protocol + " " + address
                + (key.port() != 0 ? ":" + key.port() : "") + " refused "
                + (count == 1 ? "once" : count + " times") + ": " + String.join(", ", reasons);
    }

    /** A boot time as the time of day. */
    private String timeOf(long bootNanos) {
        long wall = mService.clock().millis()
                - (SystemClock.elapsedRealtimeNanos() - bootNanos) / 1_000_000;
        LocalTime time = LocalTime.ofInstant(Instant.ofEpochMilli(wall), ZoneId.systemDefault());
        return DateTimeFormatter.ISO_LOCAL_TIME.format(time.withNano(0));
    }

}
