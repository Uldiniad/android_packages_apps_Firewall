/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.content.Intent;
import android.os.MessageQueue;
import android.os.SystemClock;
import android.os.UserHandle;
import android.util.Pair;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlSerializer;

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Each user's activity log, which the user turns on: what the BPF programs let through and what
 * they refused, with the names apps looked up, and the lookups the firewall refused, from the
 * resolver's reports. The service holds new entries only until the user's firewall app takes them
 * into its own storage.
 */
final class ActivityLog extends Feature {
    static final String ACTION_ACTIVITY = "org.lineageos.firewall.action.ACTIVITY";
    /** Entries a user's firewall app hasn't taken yet, past which the oldest go. */
    private static final int MAX_PENDING = 4096;
    /** The names apps looked up, by app and address, past which the least recent go. */
    private static final int MAX_NAMES = 4096;
    /** How long new entries wait for the firewall app, so a burst goes over at once. */
    private static final long DELIVERY_DELAY_MS = 10_000;
    private static final int MAX_RECENT = 100;
    /** A refused lookup again within this long counts with the entry before. */
    private static final long LOOKUP_REPEAT_MS = 60_000;
    // The resolver's results, from netdb.h, for a blocked app's lookups and for lookups or answers
    // the firewall refused.
    private static final int EAI_FAIL = 4;
    private static final int EAI_SYSTEM = 11;

    /** Users whose log is on. */
    final Set<Integer> users = new TreeSet<>();
    /** Each user's entries the firewall app hasn't taken, by key. */
    private final Map<Integer, LinkedHashMap<String, ActivityEntry>> mPending = new HashMap<>();
    /** Each app's latest refused lookup of a name, which repeats add to, by user, app and name. */
    private final LinkedHashMap<String, ActivityEntry> mLatestLookups =
            new LinkedHashMap<>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, ActivityEntry> eldest) {
                    return size() > MAX_NAMES;
                }
            };
    private final LinkedHashMap<Pair<Integer, InetAddress>, String> mNames =
            new LinkedHashMap<>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<Pair<Integer, InetAddress>, String> e) {
                    return size() > MAX_NAMES;
                }
            };
    private final Set<Integer> mDeliveries = new HashSet<>();
    /** The latest entries, also those taken, for the shell's list. */
    private final LinkedHashMap<String, ActivityEntry> mRecent = new LinkedHashMap<>() {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, ActivityEntry> eldest) {
            return size() > MAX_RECENT;
        }
    };
    private boolean mListening;

    ActivityLog(FirewallService service) {
        super(service);
    }

    @Override
    void clearStore() {
        users.clear();
    }

    @Override
    boolean readStoreTag(XmlPullParser parser) {
        if (!"activity-log".equals(parser.getName())) return false;
        users.add(Integer.parseInt(parser.getAttributeValue(null, "user")));
        return true;
    }

    @Override
    void writeStore(XmlSerializer serializer) throws IOException {
        for (int user : users) {
            serializer.startTag(null, "activity-log");
            serializer.attribute(null, "user", Integer.toString(user));
            serializer.endTag(null, "activity-log");
        }
    }

    @Override
    void onLoadedLocked(Set<Integer> loaded) {
        users.retainAll(loaded);
    }

    @Override
    void onStarted() {
        synchronized (mService) {
            if (!users.isEmpty()) listenLocked();
        }
    }

    /** The flags written only through the rules for all apps reach the maps here too. */
    @Override
    void onStartSyncedLocked() {
        for (int user : List.copyOf(users)) mService.syncUserLocked(user);
    }

    @Override
    boolean forgetUserLocked(int userId) {
        mPending.remove(userId);
        mRecent.values().removeIf(entry -> UserHandle.getUserId(entry.uid) == userId);
        mNames.keySet().removeIf(key -> UserHandle.getUserId(key.first) == userId);
        mLatestLookups.keySet().removeIf(flow -> flow.startsWith(userId + "/"));
        return users.remove(userId);
    }

    @Override
    void dumpLocked(PrintWriter pw) {
        pw.println("Activity logs on for users: " + users);
        mPending.forEach((user, pending) -> pw.println("  user " + user + ": " + pending.size()
                + " entries waiting for the firewall app"));
        pw.println("  names known: " + mNames.size());
    }

    int userFlagsLocked(int userId) {
        return users.contains(userId) ? FirewallMaps.USER_LOG : 0;
    }

    /** Starts taking the resolver's reports, once some user's log is on. */
    private void listenLocked() {
        mService.maps().setLookupsWanted(true);
        if (mListening || !mService.mapsReady()) return;
        FileDescriptor fd = mService.maps().listenForLookups();
        if (fd == null) return;
        mListening = true;
        mService.handler().getLooper().getQueue().addOnFileDescriptorEventListener(fd,
                MessageQueue.OnFileDescriptorEventListener.EVENT_INPUT,
                (ready, events) -> {
                    List<Maps.Lookup> lookups = mService.maps().consumeLookups();
                    synchronized (mService) {
                        onLookupsLocked(lookups);
                    }
                    return MessageQueue.OnFileDescriptorEventListener.EVENT_INPUT;
                });
    }

    /** Keeps the names apps looked up, and logs the lookups the firewall refused. */
    void onLookupsLocked(List<Maps.Lookup> lookups) {
        long now = mService.clock().millis();
        for (Maps.Lookup lookup : lookups) {
            int user = UserHandle.getUserId(lookup.uid());
            if (!users.contains(user)) continue;
            if (lookup.result() == 0) {
                for (InetAddress address : lookup.addresses()) {
                    mNames.put(Pair.create(lookup.uid(), address), lookup.name());
                }
                continue;
            }
            int reasons = lookup.result() == EAI_FAIL ? IFirewall.REASON_ALL
                    : lookup.result() == EAI_SYSTEM ? IFirewall.REASON_DOMAIN : 0;
            if (reasons == 0) continue;
            String flow = user + "/" + lookup.uid() + "/" + lookup.name();
            ActivityEntry entry = mLatestLookups.get(flow);
            if (entry == null || now - entry.lastMillis > LOOKUP_REPEAT_MS) {
                entry = new ActivityEntry();
                entry.key = "lookup/" + lookup.uid() + "/" + lookup.name() + "/" + now;
                entry.uid = lookup.uid();
                entry.kind = IFirewall.ACTIVITY_LOOKUP;
                entry.name = lookup.name();
                entry.firstMillis = now;
                mLatestLookups.put(flow, entry);
            }
            entry.reasons |= reasons;
            entry.lastMillis = now;
            entry.count++;
            addLocked(user, entry);
        }
    }

    /** Logs what the BPF programs reported for users whose log is on. */
    void onTrafficLocked(List<Maps.Refusal> reports) {
        long bootToWall = mService.clock().millis() - SystemClock.elapsedRealtime();
        for (Maps.Refusal report : reports) {
            Maps.RefusalKey key = report.key();
            int user = UserHandle.getUserId(key.uid());
            if (!users.contains(user)) continue;
            ActivityEntry entry = new ActivityEntry();
            // The same as long as the BPF programs count the flow as one.
            entry.key = key.uid() + "/" + key.direction() + "/" + key.protocol() + "/"
                    + key.address().getHostAddress() + "/" + key.port() + "/" + key.allowed()
                    + "/" + report.firstNanos();
            ActivityEntry before = pendingEntry(user, entry.key);
            entry.uid = key.uid();
            entry.kind = key.direction();
            entry.protocol = key.protocol();
            entry.address = key.address().getHostAddress();
            entry.port = key.port();
            entry.name = mNames.get(Pair.create(key.uid(), key.address()));
            entry.allowed = key.allowed();
            entry.reasons = report.reasons() | (before != null ? before.reasons : 0);
            NetworkTracker networks = mService.networks();
            int network = report.ifindex() != 0 ? networks.transportOfInterface(report.ifindex())
                    : networks.transportOfNetwork(report.netId());
            entry.network = network != 0 ? network : before != null ? before.network : 0;
            entry.firstMillis = bootToWall + report.firstNanos() / 1_000_000;
            entry.lastMillis = bootToWall + report.lastNanos() / 1_000_000;
            entry.count = report.count();
            addLocked(user, entry);
        }
    }

    private ActivityEntry pendingEntry(int user, String key) {
        LinkedHashMap<String, ActivityEntry> pending = mPending.get(user);
        return pending == null || key == null ? null : pending.get(key);
    }

    private void addLocked(int user, ActivityEntry entry) {
        LinkedHashMap<String, ActivityEntry> pending =
                mPending.computeIfAbsent(user, u -> new LinkedHashMap<>());
        pending.remove(entry.key);
        pending.put(entry.key, entry);
        mRecent.remove(entry.key);
        mRecent.put(entry.key, entry);
        if (pending.size() > MAX_PENDING) pending.remove(pending.keySet().iterator().next());
        if (mDeliveries.add(user)) {
            mService.handler().postDelayed(() -> deliver(user), DELIVERY_DELAY_MS);
        }
    }

    /** Tells the user's firewall app there are entries to take. */
    private void deliver(int user) {
        synchronized (mService) {
            mDeliveries.remove(user);
            if (!mPending.containsKey(user)) return;
        }
        mService.context().sendBroadcastAsUser(
                new Intent(ACTION_ACTIVITY).setPackage(FirewallService.APP_PACKAGE),
                UserHandle.of(user), FirewallService.PERMISSION);
    }

    void setActivityLogInternal(int userId, boolean on) {
        synchronized (mService) {
            if (on ? !users.add(userId) : !users.remove(userId)) return;
            if (on) {
                listenLocked();
            } else if (users.isEmpty()) {
                mService.maps().setLookupsWanted(false);
                mNames.clear();
            }
            if (mService.mapsReady()) mService.syncUserLocked(userId);
        }
        mService.saveAsync();
    }

    boolean isActivityLogInternal(int userId) {
        synchronized (mService) {
            return users.contains(userId);
        }
    }

    /** The user's entries since the last call, which the firewall app keeps from then on. */
    ActivityEntry[] takeActivityInternal(int userId) {
        synchronized (mService) {
            LinkedHashMap<String, ActivityEntry> pending = mPending.remove(userId);
            return pending == null ? new ActivityEntry[0]
                    : pending.values().toArray(new ActivityEntry[0]);
        }
    }

    void clearActivityInternal(int userId) {
        synchronized (mService) {
            mPending.remove(userId);
            mRecent.values().removeIf(entry -> UserHandle.getUserId(entry.uid) == userId);
            mLatestLookups.keySet().removeIf(flow -> flow.startsWith(userId + "/"));
        }
    }

    @Override
    Integer onShellCommand(String cmd, FirewallShellCommand shell) {
        PrintWriter pw = shell.getOutPrintWriter();
        switch (cmd) {
            case "set-activity-log" -> {
                String state = shell.getNextArgRequired();
                if (!state.equals("on") && !state.equals("off")) {
                    throw new IllegalArgumentException("Expected on or off: " + state);
                }
                setActivityLogInternal(shell.parseUser(), state.equals("on"));
            }
            case "get-activity-log" ->
                    pw.println(isActivityLogInternal(shell.parseUser()) ? "on" : "off");
            case "list-activity" -> {
                int user = shell.parseUser();
                List<ActivityEntry> entries = new ArrayList<>();
                synchronized (mService) {
                    for (ActivityEntry entry : mRecent.values()) {
                        if (UserHandle.getUserId(entry.uid) == user) entries.add(entry);
                    }
                }
                for (ActivityEntry entry : entries) {
                    pw.println(entry.uid + " " + (entry.allowed ? "allowed" : "refused") + " "
                            + entry.kind + " " + entry.protocol + " " + entry.address + ":"
                            + entry.port + " " + entry.name + " " + entry.network + " x"
                            + entry.count);
                }
            }
            default -> {
                return null;
            }
        }
        return 0;
    }

    @Override
    void onShellHelp(PrintWriter pw) {
        pw.println("  set-activity-log on|off [--user USER]");
        pw.println("  get-activity-log [--user USER]");
        pw.println("  list-activity [--user USER]  (the latest entries)");
    }
}
