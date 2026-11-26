/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.app.ActivityManager;
import android.app.KeyguardManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.PowerManager;
import android.os.UserHandle;
import android.os.UserManager;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlSerializer;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

/**
 * Blocks apps while their user is locked: the screen is off or the lock screen shows, or another
 * user is in front. An app is blocked then with BLOCK_LOCKED among its switches, as are all of a
 * user's apps once the user chooses it, but those with ALLOW_LOCKED. The programs read whether
 * each user is locked, so the screen going off is one map write per user, and it stops the
 * connections already open too.
 */
final class LockedBlocking extends Feature {
    /** Users all of whose apps are blocked while they're locked, but those let through. */
    final Set<Integer> blockAll = new TreeSet<>();
    /** The users unlocked at the last check: the one in front and its profiles. */
    private final Set<Integer> mUnlocked = new TreeSet<>();
    /** Whether the lock was checked yet, once the system is up; until then no user is locked. */
    private boolean mChecked;

    LockedBlocking(FirewallService service) {
        super(service);
    }

    @Override
    void clearStore() {
        blockAll.clear();
    }

    @Override
    boolean readStoreTag(XmlPullParser parser) {
        if (!"block-while-locked".equals(parser.getName())) return false;
        blockAll.add(Integer.parseInt(parser.getAttributeValue(null, "user")));
        return true;
    }

    @Override
    void writeStore(XmlSerializer serializer) throws IOException {
        for (int user : blockAll) {
            serializer.startTag(null, "block-while-locked");
            serializer.attribute(null, "user", Integer.toString(user));
            serializer.endTag(null, "block-while-locked");
        }
    }

    @Override
    void onLoadedLocked(Set<Integer> users) {
        blockAll.retainAll(users);
    }

    @Override
    boolean forgetUserLocked(int userId) {
        return blockAll.remove(userId);
    }

    @Override
    Object backupUserLocked(int userId) {
        return blockAll.contains(userId) ? Boolean.TRUE : null;
    }

    @Override
    void writeBackupAttributes(Object part, boolean user, XmlSerializer serializer)
            throws IOException {
        if (user) serializer.attribute(null, "blockWhileLocked", "true");
    }

    @Override
    Object readBackupAttributes(XmlPullParser parser, boolean user) {
        return user && "true".equals(parser.getAttributeValue(null, "blockWhileLocked"))
                ? Boolean.TRUE : null;
    }

    @Override
    void restoreUserLocked(int userId, Object part) {
        if (part != null) blockAll.add(userId);
    }

    /** Every user's flags say whether it's locked, as the rules for all apps may not write them. */
    @Override
    void onStartSyncedLocked() {
        writeAllLocked();
    }

    /** A user may have come since. */
    @Override
    void onResyncLocked() {
        writeAllLocked();
    }

    private void writeAllLocked() {
        if (!mService.mapsReady() || mService.offLocked()) return;
        TargetRules rules = mService.feature(TargetRules.class);
        if (rules == null) return;
        for (UserHandle user : mService.context().getSystemService(UserManager.class)
                .getUserHandles(false)) {
            rules.writeUserFlagsLocked(user.getIdentifier());
        }
    }

    /** Follows the screen, the lock screen and the user in front. */
    @Override
    void onBootPhase() {
        Context context = mService.context();
        IntentFilter filter = new IntentFilter(Intent.ACTION_SCREEN_ON);
        filter.addAction(Intent.ACTION_SCREEN_OFF);
        filter.addAction(Intent.ACTION_USER_SWITCHED);
        context.registerReceiverForAllUsers(new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                check();
            }
        }, filter, null, mService.handler());
        context.getSystemService(KeyguardManager.class).addKeyguardLockedStateListener(
                mService.handler()::post, locked -> check());
        check();
    }

    private void check() {
        Context context = mService.context();
        boolean unlocked = context.getSystemService(PowerManager.class).isInteractive()
                && !context.getSystemService(KeyguardManager.class).isKeyguardLocked();
        synchronized (mService) {
            onLockStateLocked(unlocked ? ActivityManager.getCurrentUser() : UserHandle.USER_NULL);
        }
    }

    /**
     * The user in front is unlocked, with its profiles, or none is, with USER_NULL: writes the
     * flags of the users whose state changed.
     */
    void onLockStateLocked(int unlockedUser) {
        Set<Integer> unlocked = new TreeSet<>();
        if (unlockedUser != UserHandle.USER_NULL) {
            for (int profile : mService.context().getSystemService(UserManager.class)
                    .getEnabledProfileIds(unlockedUser)) {
                unlocked.add(profile);
            }
            unlocked.add(unlockedUser);
        }
        Set<Integer> changed = new HashSet<>(unlocked);
        changed.addAll(mUnlocked);
        changed.removeIf(user -> unlocked.contains(user) && mUnlocked.contains(user));
        boolean first = !mChecked;
        mChecked = true;
        mUnlocked.clear();
        mUnlocked.addAll(unlocked);
        if (first) {
            writeAllLocked();
            return;
        }
        if (!mService.mapsReady() || mService.offLocked()) return;
        TargetRules rules = mService.feature(TargetRules.class);
        if (rules == null) return;
        for (int user : changed) rules.writeUserFlagsLocked(user);
    }

    private boolean lockedLocked(int userId) {
        return mChecked && !mUnlocked.contains(userId);
    }

    /** The user's flags for the programs: whether it's locked, and if all its apps are then. */
    int userFlagsLocked(int userId) {
        int flags = blockAll.contains(userId) ? FirewallMaps.USER_BLOCK_LOCKED : 0;
        return lockedLocked(userId) ? flags | FirewallMaps.USER_LOCKED : flags;
    }

    /**
     * Why the uid is blocked now as its user is locked, as REASON_* bits: its own switch or the
     * rules for all apps; 0 when it isn't. For lookups, which the resolver refuses without one.
     */
    int lockedReasonsLocked(int uid) {
        int user = UserHandle.getUserId(uid);
        if (!lockedLocked(user)) return 0;
        int rules = mService.uidRulesLocked(uid);
        if ((rules & FirewallMaps.BLOCK_LOCKED) != 0) return IFirewall.REASON_LOCKED;
        if (blockAll.contains(user) && UserHandle.isApp(uid)
                && (rules & FirewallMaps.ALLOW_LOCKED) == 0) {
            return IFirewall.REASON_USER_LOCKED;
        }
        return 0;
    }

    void setBlockedWhileLockedInternal(int userId, boolean blocked) {
        synchronized (mService) {
            if (blocked ? blockAll.add(userId) : blockAll.remove(userId)) {
                mService.syncUserLocked(userId);
            }
        }
        mService.saveAsync();
    }

    boolean isBlockedWhileLockedInternal(int userId) {
        synchronized (mService) {
            return blockAll.contains(userId);
        }
    }

    @Override
    void dumpLocked(PrintWriter pw) {
        pw.println("All apps blocked while locked for users: " + blockAll);
        pw.println("  unlocked now: " + (mChecked ? mUnlocked : "not checked yet"));
    }

    @Override
    Integer onShellCommand(String cmd, FirewallShellCommand shell) {
        switch (cmd) {
            case "set-block-while-locked" -> {
                boolean blocked = Boolean.parseBoolean(shell.getNextArgRequired());
                setBlockedWhileLockedInternal(shell.parseUser(), blocked);
            }
            case "get-block-while-locked" -> shell.getOutPrintWriter().println(
                    isBlockedWhileLockedInternal(shell.parseUser()));
            default -> {
                return null;
            }
        }
        return 0;
    }

    @Override
    void onShellHelp(PrintWriter pw) {
        pw.println("  set-block-while-locked true|false [--user USER]");
        pw.println("      Blocks all of the user's apps while it's locked, but those set with");
        pw.println("      allow-locked; set-app's locked blocks one app then.");
        pw.println("  get-block-while-locked [--user USER]");
    }
}
