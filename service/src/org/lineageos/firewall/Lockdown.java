/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.os.UserHandle;
import android.os.UserManager;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlSerializer;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Set;
import java.util.TreeSet;

/**
 * Lockdown, as NetGuard's: a user's apps are all blocked, before any rule, but those with
 * ALLOW_LOCKDOWN, and the main user's takes the hotspot's devices off the network too. Android's
 * own uids keep working. It's in the user flags the programs read, so a quick settings tile turns
 * it on and off with one map write. A mode rather than a rule, it stays out of backups.
 */
final class Lockdown extends Feature {
    /** Users in lockdown. */
    final Set<Integer> users = new TreeSet<>();

    Lockdown(FirewallService service) {
        super(service);
    }

    @Override
    void clearStore() {
        users.clear();
    }

    @Override
    boolean readStoreTag(XmlPullParser parser) {
        if (!"lockdown".equals(parser.getName())) return false;
        users.add(Integer.parseInt(parser.getAttributeValue(null, "user")));
        return true;
    }

    @Override
    void writeStore(XmlSerializer serializer) throws IOException {
        for (int user : users) {
            serializer.startTag(null, "lockdown");
            serializer.attribute(null, "user", Integer.toString(user));
            serializer.endTag(null, "lockdown");
        }
    }

    @Override
    void onLoadedLocked(Set<Integer> loaded) {
        users.retainAll(loaded);
    }

    /** A restore, which forgets the user's state first, keeps the mode; a removed user's goes. */
    @Override
    boolean forgetUserLocked(int userId) {
        if (mService.context().getSystemService(UserManager.class).getUserHandles(true)
                .contains(UserHandle.of(userId))) {
            return false;
        }
        return users.remove(userId);
    }

    /** The rules for all apps write only the flags of users with some. */
    @Override
    void onStartSyncedLocked() {
        TargetRules rules = mService.feature(TargetRules.class);
        if (rules == null) return;
        for (int user : users) rules.writeUserFlagsLocked(user);
    }

    int userFlagsLocked(int userId) {
        return users.contains(userId) ? FirewallMaps.USER_LOCKDOWN : 0;
    }

    /**
     * REASON_LOCKDOWN when the user's lockdown blocks the uid now, else 0. For lookups, which the
     * resolver refuses without one.
     */
    int lockdownReasonsLocked(int uid) {
        if (!users.contains(UserHandle.getUserId(uid)) || !UserHandle.isApp(uid)) return 0;
        return (mService.uidRulesLocked(uid) & FirewallMaps.ALLOW_LOCKDOWN) == 0
                ? IFirewall.REASON_LOCKDOWN : 0;
    }

    void setLockdownInternal(int userId, boolean on) {
        synchronized (mService) {
            if (!(on ? users.add(userId) : users.remove(userId))) return;
            TargetRules rules = mService.feature(TargetRules.class);
            if (rules != null && mService.mapsReady() && !mService.offLocked()) {
                rules.writeUserFlagsLocked(userId);
            }
        }
        mService.saveAsync();
    }

    boolean isLockdownInternal(int userId) {
        synchronized (mService) {
            return users.contains(userId);
        }
    }

    @Override
    void dumpLocked(PrintWriter pw) {
        pw.println("Lockdown for users: " + users);
    }

    @Override
    Integer onShellCommand(String cmd, FirewallShellCommand shell) {
        switch (cmd) {
            case "set-lockdown" -> {
                boolean on = Boolean.parseBoolean(shell.getNextArgRequired());
                setLockdownInternal(shell.parseUser(), on);
            }
            case "get-lockdown" ->
                    shell.getOutPrintWriter().println(isLockdownInternal(shell.parseUser()));
            default -> {
                return null;
            }
        }
        return 0;
    }

    @Override
    void onShellHelp(PrintWriter pw) {
        pw.println("  set-lockdown true|false [--user USER]");
        pw.println("      Blocks all of the user's apps but those set with allow-lockdown.");
        pw.println("  get-lockdown [--user USER]");
    }
}
