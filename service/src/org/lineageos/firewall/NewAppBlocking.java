/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.Manifest;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.ApplicationInfoFlags;
import android.os.UserHandle;
import android.util.Pair;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlSerializer;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Predicate;

/**
 * New apps that start blocked until their user decides, with a notice offering to allow them:
 * every new install of users who chose it, and user-installed apps that lack INTERNET, so an
 * update adding it doesn't silently get network.
 */
final class NewAppBlocking extends Feature {
    /** Sent to the firewall app when a new app is blocked until the user decides. */
    static final String ACTION_APP_BLOCKED = "org.lineageos.firewall.action.APP_BLOCKED";

    /** Apps whose rules are a new-install default rather than the user's decision. */
    final Set<Pair<String, Integer>> defaults = new HashSet<>();
    /** Defaults the user was told about, so they hear about each once. */
    final Set<Pair<String, Integer>> notified = new HashSet<>();
    /** Users whose new installs start blocked. */
    final Set<Integer> blockNewInstalls = new TreeSet<>();

    /** An app's marks as backed up. */
    private record Marks(boolean isDefault, boolean notified) {}

    NewAppBlocking(FirewallService service) {
        super(service);
    }

    @Override
    Object backupAppLocked(Pair<String, Integer> app) {
        boolean isDefault = defaults.contains(app);
        boolean told = notified.contains(app);
        return isDefault || told ? new Marks(isDefault, told) : null;
    }

    @Override
    Object backupUserLocked(int userId) {
        return blockNewInstalls.contains(userId) ? Boolean.TRUE : null;
    }

    @Override
    void writeBackupAttributes(Object part, boolean user, XmlSerializer serializer)
            throws IOException {
        if (user) {
            serializer.attribute(null, "blockNewInstalls", "true");
            return;
        }
        Marks marks = (Marks) part;
        if (marks.isDefault()) serializer.attribute(null, "default", "true");
        if (marks.notified()) serializer.attribute(null, "notified", "true");
    }

    @Override
    Object readBackupAttributes(XmlPullParser parser, boolean user) {
        if (user) {
            return "true".equals(parser.getAttributeValue(null, "blockNewInstalls"))
                    ? Boolean.TRUE : null;
        }
        boolean isDefault = "true".equals(parser.getAttributeValue(null, "default"));
        boolean told = "true".equals(parser.getAttributeValue(null, "notified"));
        return isDefault || told ? new Marks(isDefault, told) : null;
    }

    /** The marks come with the app's switches, so they apply when those do. */
    @Override
    void restoreAppLocked(Pair<String, Integer> app, FirewallBackup.App restored) {
        if (restored.rules() < 0) return;
        defaults.remove(app);
        notified.remove(app);
        Marks marks = (Marks) restored.parts().get(this);
        if (marks == null) return;
        if (marks.isDefault()) defaults.add(app);
        if (marks.notified()) notified.add(app);
    }

    @Override
    void restoreUserLocked(int userId, Object part) {
        if (part != null) blockNewInstalls.add(userId);
    }

    @Override
    void clearStore() {
        defaults.clear();
        notified.clear();
        blockNewInstalls.clear();
    }

    @Override
    void readAppAttributes(Pair<String, Integer> app, XmlPullParser parser) {
        if ("true".equals(parser.getAttributeValue(null, "default"))) defaults.add(app);
        if ("true".equals(parser.getAttributeValue(null, "notified"))) notified.add(app);
    }

    @Override
    void writeAppAttributes(Pair<String, Integer> app, XmlSerializer serializer)
            throws IOException {
        if (defaults.contains(app)) serializer.attribute(null, "default", "true");
        if (notified.contains(app)) serializer.attribute(null, "notified", "true");
    }

    @Override
    boolean readStoreTag(XmlPullParser parser) {
        if (!"user".equals(parser.getName())) return false;
        if ("true".equals(parser.getAttributeValue(null, "blockNewInstalls"))) {
            blockNewInstalls.add(Integer.parseInt(parser.getAttributeValue(null, "id")));
        }
        return true;
    }

    @Override
    void writeStore(XmlSerializer serializer) throws IOException {
        for (int user : blockNewInstalls) {
            serializer.startTag(null, "user");
            serializer.attribute(null, "id", Integer.toString(user));
            serializer.attribute(null, "blockNewInstalls", "true");
            serializer.endTag(null, "user");
        }
    }

    @Override
    void onSaveLocked() {
        defaults.retainAll(mService.store().apps.keySet());
        notified.retainAll(defaults);
    }

    @Override
    void onLoadedLocked(Set<Integer> users) {
        defaults.retainAll(mService.store().apps.keySet());
        blockNewInstalls.retainAll(users);
    }

    /**
     * Apps from before the firewall start as new installs would, so those without INTERNET
     * need the user's OK once an update adds it.
     */
    @Override
    void onStartLocked(Set<Integer> users, boolean firstStart) {
        if (!firstStart) return;
        for (int user : users) {
            PackageManager pm = mService.context().createContextAsUser(UserHandle.of(user), 0)
                    .getPackageManager();
            for (ApplicationInfo app : pm.getInstalledApplications(
                    ApplicationInfoFlags.of(FirewallService.PACKAGE_FLAGS))) {
                applyNewInstallDefaultLocked(app.packageName, app.uid);
            }
        }
    }

    @Override
    boolean onPackageAddedLocked(Pair<String, Integer> app, int uid) {
        boolean changed = applyNewInstallDefaultLocked(app.first, uid);
        return notifyIfBlockedLocked(app, uid) || changed;
    }

    /**
     * An update adding INTERNET to a new app that started blocked. Android tells permission
     * listeners only about runtime permissions, so this comes from the package callback.
     */
    @Override
    boolean onPackageUpdatedLocked(Pair<String, Integer> app, int uid) {
        return notifyIfBlockedLocked(app, uid);
    }

    /**
     * An archived app can come back as a first install, so an app without rules is recorded as
     * allowed to come back as it was.
     */
    @Override
    boolean onArchivingLocked(Pair<String, Integer> app) {
        return mService.store().apps.putIfAbsent(app, 0) == null;
    }

    @Override
    void onDecisionLocked(Pair<String, Integer> app) {
        defaults.remove(app);
        notified.remove(app);
    }

    /** Tells the users about the apps that started blocked while the firewall was off. */
    @Override
    void onTurnedOnLocked() {
        for (Pair<String, Integer> app : defaults) {
            int uid = mService.packageUid(app, FirewallService.PACKAGE_FLAGS);
            if (uid >= 0) notifyIfBlockedLocked(app, uid);
        }
    }

    @Override
    boolean forgetAppsLocked(Predicate<Pair<String, Integer>> gone) {
        defaults.retainAll(mService.store().apps.keySet());
        return false;
    }

    @Override
    boolean forgetUserLocked(int userId) {
        defaults.removeIf(app -> app.second == userId);
        notified.removeIf(app -> app.second == userId);
        return blockNewInstalls.remove(userId);
    }

    @Override
    void fillAppRuleLocked(Pair<String, Integer> app, AppRule rule) {
        rule.isDefault = defaults.contains(app);
        rule.notified = notified.contains(app);
    }

    @Override
    void describeAppLocked(Pair<String, Integer> app, StringBuilder line) {
        if (defaults.contains(app)) {
            line.append(notified.contains(app) ? " (default, notified)" : " (default)");
        }
    }

    @Override
    void dumpLocked(PrintWriter pw) {
        pw.println("New installs start blocked for users: " + blockNewInstalls);
    }

    /**
     * Starts a user-installed app blocked when it lacks INTERNET, so an update adding it doesn't
     * silently get network, or when its user blocks new installs. A decision or a restored rule
     * wins.
     */
    boolean applyNewInstallDefaultLocked(String packageName, int uid) {
        if (uid < 0) return false;
        int userId = UserHandle.getUserHandleForUid(uid).getIdentifier();
        Pair<String, Integer> app = Pair.create(packageName, userId);
        if (mService.store().apps.containsKey(app) || mService.groupOfLocked(app) != null
                || !mService.userInstalled(app)) {
            return false;
        }
        boolean lacksInternet = mService.context().checkPermission(
                Manifest.permission.INTERNET, -1, uid) != PackageManager.PERMISSION_GRANTED;
        if (!lacksInternet && !blockNewInstalls.contains(userId)) return false;
        mService.store().apps.put(app, FirewallMaps.BLOCK_ALL);
        defaults.add(app);
        return true;
    }

    /**
     * Tells the user once about an app blocked until they decide, as soon as it can use the
     * network: its first connection can't tell, as Android's resolver refuses its lookups.
     */
    boolean notifyIfBlockedLocked(Pair<String, Integer> app, int uid) {
        // The app isn't blocked while the firewall is off, so it's told once it's back on.
        if (mService.offLocked()) return false;
        if (!defaults.contains(app) || notified.contains(app)
                || mService.context().checkPermission(Manifest.permission.INTERNET, -1, uid)
                        != PackageManager.PERMISSION_GRANTED) {
            return false;
        }
        notified.add(app);
        // The firewall app tells the user, who can allow the app or keep it blocked.
        mService.handler().post(() -> mService.context().sendBroadcastAsUser(
                new Intent(ACTION_APP_BLOCKED)
                        .setPackage(FirewallService.APP_PACKAGE)
                        .putExtra(Intent.EXTRA_PACKAGE_NAME, app.first),
                UserHandle.of(app.second), FirewallService.PERMISSION));
        return true;
    }

    /** Whether the app's rules are a new-install default the user hasn't decided on. */
    boolean isDefaultInternal(String packageName, int userId) {
        synchronized (mService) {
            return defaults.contains(Pair.create(packageName, userId));
        }
    }

    void setNewInstallsBlockedInternal(int userId, boolean blocked) {
        synchronized (mService) {
            if (blocked) {
                blockNewInstalls.add(userId);
            } else {
                blockNewInstalls.remove(userId);
            }
        }
        mService.saveAsync();
    }

    boolean areNewInstallsBlockedInternal(int userId) {
        synchronized (mService) {
            return blockNewInstalls.contains(userId);
        }
    }

    @Override
    Integer onShellCommand(String cmd, FirewallShellCommand shell) {
        switch (cmd) {
            case "set-new-installs" -> {
                String state = shell.getNextArgRequired();
                if (!state.equals("blocked") && !state.equals("allowed")) {
                    throw new IllegalArgumentException("Unknown state " + state);
                }
                setNewInstallsBlockedInternal(shell.parseUser(), state.equals("blocked"));
            }
            case "get-new-installs" -> shell.getOutPrintWriter().println(
                    areNewInstallsBlockedInternal(shell.parseUser()) ? "blocked" : "allowed");
            default -> {
                return null;
            }
        }
        return 0;
    }

    @Override
    void onShellHelp(PrintWriter pw) {
        pw.println("  set-new-installs blocked|allowed [--user USER]");
        pw.println("  get-new-installs [--user USER]");
    }
}
