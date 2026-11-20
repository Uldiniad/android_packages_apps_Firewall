/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

package org.lineageos.firewall;

import android.content.pm.PackageManager;
import android.content.pm.PackageManager.PackageInfoFlags;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.UserHandle;
import android.util.Log;
import android.util.Pair;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlSerializer;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * The rules in Android's backup, for the firewall app's backup agent: a user's switches and every
 * feature's part, restored to apps signed as when backed up, and kept for apps not installed yet.
 */
final class BackupRestore extends Feature {
    /** Restored rules of apps not installed yet, applied when they are. */
    final Map<Pair<String, Integer>, FirewallBackup.App> pending = new HashMap<>();

    BackupRestore(FirewallService service) {
        super(service);
    }

    @Override
    void clearStore() {
        pending.clear();
    }

    @Override
    boolean readStoreTag(XmlPullParser parser) throws IOException, XmlPullParserException {
        if (!"pending".equals(parser.getName())) return false;
        pending.put(FirewallStore.appOf(parser),
                FirewallBackup.readApp(parser, mService.features()));
        return true;
    }

    @Override
    void writeStore(XmlSerializer serializer) throws IOException {
        for (Map.Entry<Pair<String, Integer>, FirewallBackup.App> app : pending.entrySet()) {
            FirewallBackup.writeApp(serializer, "pending", app.getValue(), app.getKey().second,
                    mService.features());
        }
    }

    @Override
    void onLoadedLocked(Set<Integer> users) {
        pending.keySet().removeIf(app -> !users.contains(app.second));
    }

    /** A restored rule waiting for the app wins over what other features would give it. */
    @Override
    boolean onPackageAddedLocked(Pair<String, Integer> app, int uid) {
        FirewallBackup.App restored = pending.remove(app);
        if (restored == null) return false;
        applyRestoredLocked(app, restored);
        return true;
    }

    @Override
    boolean forgetUserLocked(int userId) {
        return pending.keySet().removeIf(app -> app.second == userId);
    }

    @Override
    void dumpLocked(PrintWriter pw) {
        pw.println("Restored rules waiting for their app:");
        pending.forEach((app, rule) -> pw.println("  " + app.first + " user " + app.second
                + " rules " + (rule.rules() < 0 ? "unset"
                        : FirewallShellCommand.rulesToString(rule.rules()))
                + ", " + rule.parts().size() + " more"));
    }

    /** Applies a restored rule to its installed app, unless another signer made the app. */
    private boolean applyRestoredLocked(Pair<String, Integer> app, FirewallBackup.App rule) {
        PackageManager pm = mService.context().createContextAsUser(UserHandle.of(app.second), 0)
                .getPackageManager();
        for (String cert : rule.certs()) {
            if (!pm.hasSigningCertificate(app.first, HexFormat.of().parseHex(cert),
                    PackageManager.CERT_INPUT_SHA256)) {
                Log.w(FirewallService.TAG, "Not restoring " + app.first + " for user "
                        + app.second + ": signed by someone else");
                return false;
            }
        }
        if (rule.rules() >= 0) mService.store().apps.put(app, rule.rules());
        for (Feature feature : mService.features()) feature.restoreAppLocked(app, rule);
        return true;
    }

    /** SHA-256 digests of the certificates the app's APK is signed with, as restores check. */
    private Set<String> certDigests(Pair<String, Integer> app) {
        try {
            SigningInfo signing = mService.context()
                    .createContextAsUser(UserHandle.of(app.second), 0).getPackageManager()
                    .getPackageInfo(app.first, PackageInfoFlags.of(FirewallService.PACKAGE_FLAGS
                            | PackageManager.GET_SIGNING_CERTIFICATES)).signingInfo;
            if (signing == null) return Set.of();
            Set<String> digests = new TreeSet<>();
            for (Signature signer : signing.getApkContentsSigners()) {
                digests.add(HexFormat.of().formatHex(
                        MessageDigest.getInstance("SHA-256").digest(signer.toByteArray())));
            }
            return digests;
        } catch (PackageManager.NameNotFoundException | NoSuchAlgorithmException e) {
            return Set.of();
        }
    }

    /** A user's rules, switch and lists, for their firewall app's backup agent. */
    byte[] getBackupPayloadInternal(int userId) {
        FirewallBackup backup = new FirewallBackup();
        synchronized (mService) {
            for (Feature feature : mService.features()) {
                backup.user.put(feature, feature.backupUserLocked(userId));
            }
            for (Pair<String, Integer> app : mService.appsWithStateLocked()) {
                if (app.second != userId) continue;
                FirewallBackup.Parts parts = new FirewallBackup.Parts();
                for (Feature feature : mService.features()) {
                    parts.put(feature, feature.backupAppLocked(app));
                }
                backup.apps.add(new FirewallBackup.App(app.first,
                        mService.store().apps.getOrDefault(app, -1), certDigests(app), parts));
            }
            // Rules still waiting for their app go along as they were restored.
            pending.forEach((app, rule) -> {
                if (app.second == userId) backup.apps.add(rule);
            });
        }
        try {
            return backup.toBytes(mService.features());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Replaces a user's rules, switch and lists with a backup's. */
    void applyRestoreInternal(int userId, byte[] payload) {
        FirewallBackup backup = FirewallBackup.fromBytes(payload, mService.features());
        synchronized (mService) {
            mService.forgetUserLocked(userId);
            for (Feature feature : mService.features()) {
                feature.restoreUserLocked(userId, backup.user.get(feature));
            }
            for (FirewallBackup.App rule : backup.apps) {
                Pair<String, Integer> app = Pair.create(rule.packageName(), userId);
                if (mService.packageUid(app, FirewallService.PACKAGE_FLAGS) < 0) {
                    pending.put(app, rule);
                } else {
                    applyRestoredLocked(app, rule);
                }
            }
            if (mService.mapsReady()) {
                mService.syncAppsLocked();
            }
        }
        mService.saveAsync();
    }

    @Override
    Integer onShellCommand(String cmd, FirewallShellCommand shell) throws IOException {
        switch (cmd) {
            case "backup" -> {
                shell.getOutPrintWriter().flush();
                shell.getRawOutputStream().write(getBackupPayloadInternal(shell.parseUser()));
            }
            case "restore" -> applyRestoreInternal(shell.parseUser(),
                    shell.getRawInputStream().readAllBytes());
            default -> {
                return null;
            }
        }
        return 0;
    }

    @Override
    void onShellHelp(PrintWriter pw) {
        pw.println("  backup [--user USER]   (writes the payload to stdout)");
        pw.println("  restore [--user USER]  (reads a payload from stdin)");
    }
}
